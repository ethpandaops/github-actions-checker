package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-github/v70/github"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

var (
	inputJSONFile string
	targetRepo    string
	branchName    string
	customPRTitle string
	prTitle       string
	customPRBody  string
	prBody        string
	allRepos      bool
	skipPR        bool
	dryRun        bool
	useFork       bool
	addDependabot bool

	createPRCmd = &cobra.Command{
		Use:   "create-pr",
		Short: "Create a PR to update GitHub Actions to use recommended hashes",
		RunE:  createPR,
	}
)

// ANSI color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"

	dependabotPath = ".github/dependabot.yml"
)

func init() {
	createPRCmd.Flags().StringVarP(&inputJSONFile, "input", "i", "", "Input JSON file with action dependencies")
	createPRCmd.Flags().StringVarP(&targetRepo, "repo", "r", "", "Target repository for PR (format: owner/repo)")
	createPRCmd.Flags().StringVarP(&branchName, "branch", "b", "update-github-actions", "Branch name for the PR")
	createPRCmd.Flags().StringVarP(&customPRTitle, "title", "t", "", "PR title")
	createPRCmd.Flags().StringVarP(&customPRBody, "body", "", "", "PR body")
	createPRCmd.Flags().BoolVarP(&allRepos, "all", "a", false, "Process all repositories in the input file")
	createPRCmd.Flags().BoolVarP(&skipPR, "skip-pr", "s", false, "Skip PR creation, only create branch with changes")
	createPRCmd.Flags().BoolVarP(&dryRun, "dry-run", "d", false, "Show what would be changed without creating branch or PR")
	createPRCmd.Flags().BoolVarP(&useFork, "fork", "f", false, "Create PR from a personal fork")
	createPRCmd.Flags().BoolVar(&addDependabot, "dependabot", true, "Add or update dependabot.yml configuration for GitHub Actions")
	createPRCmd.MarkFlagRequired("input")
	// Don't mark repo as required - we'll check it in the command
	rootCmd.AddCommand(createPRCmd)
}

func createPR(cmd *cobra.Command, args []string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	// Check if either --repo or --all is provided
	if !allRepos && targetRepo == "" {
		return fmt.Errorf("either --repo or --all flag is required")
	}

	// Read and parse the JSON file
	data, err := os.ReadFile(inputJSONFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var outputData OutputData
	if err := json.Unmarshal(data, &outputData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	deps := outputData.Workflows

	// If --all flag is set, process all repos
	if allRepos {
		// Get unique repos
		repoSet := make(map[string]bool)
		for _, dep := range deps {
			repoSet[dep.Repo] = true
		}

		// Convert to slice and sort
		repos := make([]string, 0, len(repoSet))
		for repo := range repoSet {
			repos = append(repos, repo)
		}
		sort.Strings(repos)

		// Process each repo in sorted order
		for _, repo := range repos {
			logrus.Infof("Processing repository: %s", repo)
			targetRepo = repo
			if err := processRepo(token, deps); err != nil {
				logrus.WithFields(logrus.Fields{
					"repo":  repo,
					"error": err,
				}).Error("Failed to process repository")
				// Continue with next repo instead of returning
			}
		}
		return nil
	}

	// Process single repo
	return processRepo(token, deps)
}

func processRepo(token string, deps []ActionDependency) error {
	// Parse target repo
	parts := strings.Split(targetRepo, "/")
	if len(parts) != 2 {
		return fmt.Errorf("repo must be in format owner/repo")
	}
	owner, repo := parts[0], parts[1]

	// Filter dependencies for the target repo
	var targetDeps []ActionDependency
	for _, dep := range deps {
		if dep.Repo == targetRepo {
			targetDeps = append(targetDeps, dep)
		}
	}

	if len(targetDeps) == 0 {
		return fmt.Errorf("no dependencies found for repo %s", targetRepo)
	}

	// Setup GitHub client
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Get the default branch
	repository, resp, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo":  targetRepo,
			"error": err,
			"resp":  resp.Status,
		}).Error("Failed to get repository")
		// Default to "master" if we can't get the default branch
		defaultBranch := "master"
		logrus.WithField("branch", defaultBranch).Info("Using default branch")

		// Continue with the rest of the function using the default branch
		return processRepoWithBranch(ctx, client, owner, repo, defaultBranch, branchName, targetDeps)
	}

	defaultBranch := repository.GetDefaultBranch()

	// Handle forking if requested
	if useFork && !dryRun {
		headOwner, err := getAuthenticatedUser(ctx, client)
		if err != nil {
			return fmt.Errorf("failed to get authenticated user: %w", err)
		}

		// Check if fork exists
		_, resp, err := client.Repositories.Get(ctx, headOwner, repo)
		if err != nil && resp.StatusCode == 404 {
			// Fork doesn't exist, create it
			logrus.Infof("Creating fork of %s/%s", owner, repo)
			_, _, err = client.Repositories.CreateFork(ctx, owner, repo, &github.RepositoryCreateForkOptions{})
			if err != nil {
				return fmt.Errorf("failed to create fork: %w", err)
			}

			// Wait for fork to be created
			logrus.Info("Waiting for fork to be ready...")
			err = waitForFork(ctx, client, headOwner, repo)
			if err != nil {
				return fmt.Errorf("fork creation timed out: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to check for existing fork: %w", err)
		}

		// Use the fork for the PR
		return processRepoWithFork(ctx, client, owner, repo, headOwner, defaultBranch, branchName, targetDeps)
	}

	return processRepoWithBranch(ctx, client, owner, repo, defaultBranch, branchName, targetDeps)
}

// New function to handle the repository processing with a known branch
func processRepoWithBranch(ctx context.Context, client *github.Client, owner, repo, defaultBranch, branchName string, targetDeps []ActionDependency) error {
	if !dryRun {
		// Get the reference to the default branch
		ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
		if err != nil {
			return fmt.Errorf("failed to get reference: %w", err)
		}

		// Create a new branch
		newRef := &github.Reference{
			Ref:    github.Ptr("refs/heads/" + branchName),
			Object: &github.GitObject{SHA: ref.Object.SHA},
		}

		_, _, err = client.Git.CreateRef(ctx, owner, repo, newRef)
		if err != nil {
			// If branch already exists, try to get it
			if strings.Contains(err.Error(), "Reference already exists") {
				_, _, err = client.Git.GetRef(ctx, owner, repo, "refs/heads/"+branchName)
				if err != nil {
					return fmt.Errorf("branch already exists but couldn't be retrieved: %w", err)
				}
			} else {
				return fmt.Errorf("failed to create branch: %w", err)
			}
		}
	}

	// Process workflow files and create PR
	if err := processFileChanges(ctx, client, owner, repo, owner, defaultBranch, branchName, targetDeps); err != nil {
		return err
	}

	return nil
}

// Add new function to handle forked workflow
func processRepoWithFork(ctx context.Context, client *github.Client, upstreamOwner, repo, forkOwner, defaultBranch, branchName string, targetDeps []ActionDependency) error {
	// First, sync fork with upstream to ensure we have the latest code
	if !dryRun {
		logrus.Infof("Syncing fork %s/%s with upstream %s/%s", forkOwner, repo, upstreamOwner, repo)

		// Get the reference to the default branch in the upstream repo
		upstreamRef, _, err := client.Git.GetRef(ctx, upstreamOwner, repo, "refs/heads/"+defaultBranch)
		if err != nil {
			return fmt.Errorf("failed to get upstream reference: %w", err)
		}

		// Update the default branch in the fork to match upstream
		forkRef, _, err := client.Git.GetRef(ctx, forkOwner, repo, "refs/heads/"+defaultBranch)
		if err != nil {
			return fmt.Errorf("failed to get fork reference: %w", err)
		}

		// Update fork's default branch to match upstream
		forkRef.Object.SHA = upstreamRef.Object.SHA
		_, _, err = client.Git.UpdateRef(ctx, forkOwner, repo, forkRef, false)
		if err != nil {
			return fmt.Errorf("failed to sync fork with upstream: %w", err)
		}

		// Create a new branch in the fork
		newRef := &github.Reference{
			Ref:    github.Ptr("refs/heads/" + branchName),
			Object: &github.GitObject{SHA: upstreamRef.Object.SHA},
		}

		_, _, err = client.Git.CreateRef(ctx, forkOwner, repo, newRef)
		if err != nil {
			// If branch already exists, try to get it
			if strings.Contains(err.Error(), "Reference already exists") {
				_, _, err = client.Git.GetRef(ctx, forkOwner, repo, "refs/heads/"+branchName)
				if err != nil {
					return fmt.Errorf("branch already exists but couldn't be retrieved: %w", err)
				}
			} else {
				return fmt.Errorf("failed to create branch in fork: %w", err)
			}
		}
	}

	// Process workflow files and create PR
	if err := processFileChanges(ctx, client, upstreamOwner, repo, forkOwner, defaultBranch, branchName, targetDeps); err != nil {
		return err
	}

	return nil
}

// New function to process workflow files and create PR
func processWorkflows(ctx context.Context, client *github.Client, upstreamOwner, repo, headOwner, defaultBranch, branchName string, targetDeps []ActionDependency) (map[string]bool, error) {
	// Process each workflow file
	filesChanged := make(map[string]bool)
	for _, dep := range targetDeps {
		workflowPath := dep.Workflow

		// Get the workflow file content
		var content string
		var fileContent *github.RepositoryContent

		if dryRun {
			// In dry run mode, always get from upstream default branch
			fc, _, _, err := client.Repositories.GetContents(
				ctx, upstreamOwner, repo, workflowPath,
				&github.RepositoryContentGetOptions{Ref: defaultBranch},
			)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"repo":     fmt.Sprintf("%s/%s", upstreamOwner, repo),
					"workflow": workflowPath,
					"error":    err,
				}).Error("Failed to get workflow file")
				continue
			}
			fileContent = fc
		} else {
			// Normal mode, get from the branch we created
			fc, _, _, err := client.Repositories.GetContents(
				ctx, headOwner, repo, workflowPath,
				&github.RepositoryContentGetOptions{Ref: branchName},
			)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"repo":     fmt.Sprintf("%s/%s", headOwner, repo),
					"workflow": workflowPath,
					"error":    err,
				}).Error("Failed to get workflow file")
				continue
			}
			fileContent = fc
		}

		var err error
		content, err = fileContent.GetContent()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"repo":     fmt.Sprintf("%s/%s", headOwner, repo),
				"workflow": workflowPath,
				"error":    err,
			}).Error("Failed to decode content")
			continue
		}

		// Update the content with recommended hashes
		updatedContent := content
		changed := false

		for _, action := range dep.Actions {
			if action.Type == "external" && action.IsHashedVersion {
				// Make sure that the version exists as a comment in the line
				// Replace any existing comment with the correct version
				pattern := fmt.Sprintf(`uses:\s+%s@%s(?:\s*#.*)?`,
					regexp.QuoteMeta(action.Name),
					regexp.QuoteMeta(action.Version))
				replacement := fmt.Sprintf("uses: %s@%s # %s",
					action.Name,
					action.Version,
					action.VersionHashReverseLookupVersion)

				re, err := regexp.Compile(pattern)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"pattern": pattern,
						"error":   err,
					}).Error("Failed to compile regex")
					continue
				}

				// Replace the line completely, including any existing comment
				if re.MatchString(updatedContent) {
					newContent := re.ReplaceAllString(updatedContent, replacement)
					if newContent != updatedContent {
						updatedContent = newContent
						changed = true

						if dryRun {
							fmt.Printf("%sWould update comment for %s@%s to include version %s in %s%s\n",
								colorYellow, action.Name, action.Version, action.VersionHashReverseLookupVersion,
								workflowPath, colorReset)
						} else {
							logrus.WithFields(logrus.Fields{
								"action":   action.Name,
								"version":  action.Version,
								"workflow": workflowPath,
							}).Info("Updating version comment for hashed action")
						}
					} else {
						if dryRun {
							fmt.Printf("%sNo change needed for %s@%s (already has correct comment) in %s%s\n",
								colorBlue, action.Name, action.Version, workflowPath, colorReset)
						}
					}
				}
			} else if action.Type == "external" && !action.IsHashedVersion && action.RecommendedHash != "" {
				// Create a pattern to match the action reference
				pattern := fmt.Sprintf(`uses:\s+%s@%s\b`, regexp.QuoteMeta(action.Name), regexp.QuoteMeta(action.Version))
				replacement := fmt.Sprintf("uses: %s@%s # %s", action.Name, action.RecommendedHash, action.RecommendedHashReverseLookupVersion)

				re, err := regexp.Compile(pattern)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"pattern": pattern,
						"error":   err,
					}).Error("Failed to compile regex")
					continue
				}

				if re.MatchString(updatedContent) {
					newContent := re.ReplaceAllString(updatedContent, replacement)
					if newContent != updatedContent {
						updatedContent = newContent
						changed = true

						if dryRun {
							fmt.Printf("%sWould update %s from %s to %s (%s) in %s%s\n",
								colorYellow, action.Name, action.Version, action.RecommendedHash,
								action.RecommendedHashReverseLookupVersion, workflowPath, colorReset)
						} else {
							logrus.WithFields(logrus.Fields{
								"action":   action.Name,
								"from":     action.Version,
								"to":       action.RecommendedHash,
								"workflow": workflowPath,
							}).Info("Updating action")
						}
					} else {
						if dryRun {
							fmt.Printf("%sNo change needed for %s@%s (already has correct hash) in %s%s\n",
								colorBlue, action.Name, action.Version, workflowPath, colorReset)
						}
					}
				}
			}
		}

		// If changes were made, commit the file
		if changed {
			if dryRun {
				// In dry run mode, show the diff
				fmt.Printf("\n%sChanges for %s:%s\n", colorBlue, workflowPath, colorReset)
				printDiff(content, updatedContent)
				fmt.Println()
			} else {
				// Create a commit
				opts := &github.RepositoryContentFileOptions{
					Message: github.Ptr(fmt.Sprintf("Update GitHub Actions in %s to use pinned hashes", dep.Workflow)),
					Content: []byte(updatedContent),
					Branch:  github.Ptr(branchName),
					SHA:     fileContent.SHA,
				}

				_, _, err = client.Repositories.UpdateFile(ctx, headOwner, repo, workflowPath, opts)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"repo":     fmt.Sprintf("%s/%s", headOwner, repo),
						"workflow": workflowPath,
						"error":    err,
					}).Error("Failed to update file")
					continue
				}
			}

			filesChanged[workflowPath] = true
		} else if dryRun {
			fmt.Printf("\n%sNo actual changes needed for %s%s\n", colorBlue, workflowPath, colorReset)
		}
	}

	return filesChanged, nil
}

func processFileChanges(ctx context.Context, client *github.Client, upstreamOwner, repo, headOwner, defaultBranch, branchName string, targetDeps []ActionDependency) error {
	// Process workflow files
	filesChanged, err := processWorkflows(ctx, client, upstreamOwner, repo, headOwner, defaultBranch, branchName, targetDeps)
	if err != nil {
		return err
	}

	// Process dependabot config if enabled
	if addDependabot {
		var err error
		filesChanged, err = processDependabotConfig(ctx, client, upstreamOwner, repo, branchName, dryRun, filesChanged)
		if err != nil {
			return fmt.Errorf("failed to handle dependabot config: %w", err)
		}
	}

	// Create pull request
	return createPullRequest(ctx, client, upstreamOwner, repo, headOwner, defaultBranch, branchName, filesChanged)
}

func createPullRequest(ctx context.Context, client *github.Client, upstreamOwner, repo, headOwner, defaultBranch, branchName string, filesChanged map[string]bool) error {
	// If no files were changed, check if a PR already exists and show its link
	if len(filesChanged) == 0 {
		if dryRun {
			fmt.Printf("%sNo changes would be made%s\n", colorBlue, colorReset)
		} else {
			logrus.Info("No files were changed")

			// Check if a PR already exists for this branch
			existingPRs, _, err := client.PullRequests.List(ctx, upstreamOwner, repo, &github.PullRequestListOptions{
				Head:  fmt.Sprintf("%s:%s", headOwner, branchName),
				State: "open",
			})
			if err != nil {
				return fmt.Errorf("failed to check for existing PRs: %w", err)
			}

			if len(existingPRs) > 0 {
				pr := existingPRs[0]
				fmt.Printf("Found existing PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
			} else {
				fmt.Println("No existing PR found and no changes to make")
			}
		}
		return nil
	}

	prTitle := ""
	prBody := ""
	hasWorkflowChanges := len(filesChanged) > 1 && filesChanged[dependabotPath] || len(filesChanged) > 0 && !filesChanged[dependabotPath]
	hasDependabotChanges := filesChanged[dependabotPath]

	// If no custom title is provided, generate one based on changes
	if customPRTitle == "" {
		var titleParts []string
		titleParts = append(titleParts, "chore(deps):")
		// Check for workflow changes
		if hasWorkflowChanges {
			titleParts = append(titleParts, "updating GitHub Actions to pinned hashes")
		}
		// Check for dependabot changes
		if hasDependabotChanges {
			if hasWorkflowChanges {
				titleParts = append(titleParts, "and")
			}
			titleParts = append(titleParts, "enable automatic updates for GitHub Actions via Dependabot")
		}
		prTitle = strings.Join(titleParts, " ")
	}

	if customPRBody == "" {
		var bodyParts []string
		// Check for workflow changes
		if hasWorkflowChanges {
			bodyParts = append(bodyParts, `
### 🔐 Github Actions versions pinning via commit hashes
This PR updates the GitHub Actions to use pinned hashes.

Using version tags like v1 or v2 in GitHub Actions can be risky as the action maintainer can change the underlying code of any tag, or branch.

Pinning to specific commit hashes ensures you're using a specific, immutable version of the action.`)
		}
		// Check for dependabot changes
		if hasDependabotChanges {
			bodyParts = append(bodyParts, `
### 💚 Dependabot automatic updates
This PR enables automatic updates for GitHub Actions via [Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot).

Dependabot will periodically check for new versions of the actions and create a PR to update the version used in the repository.

This should help keeping your GitHub Actions up to date with the latest versions of the actions.

#### 🔍 How was this detected and generated?
This PR was generated using [ethpandaops/github-actions-checker](https://github.com/ethpandaops/github-actions-checker).
`)
		}
		prBody = strings.Join(bodyParts, "\n\n")
	}

	if dryRun {
		fmt.Printf("\n%sWould create PR from %s/%s branch '%s' to '%s/%s' branch '%s'%s\n",
			colorBlue, headOwner, repo, branchName, upstreamOwner, repo, defaultBranch, colorReset)
		fmt.Printf("%sPR title would be:\n%s%s\n", colorYellow, colorReset, prTitle)
		fmt.Printf("%sPR body would be:%s %s\n", colorYellow, colorReset, prBody)
		return nil
	}

	// If skipPR flag is set, don't create a PR
	if skipPR {
		fmt.Printf("Changes made to branch '%s' in %s/%s. PR creation skipped as requested.\n",
			branchName, headOwner, repo)
		return nil
	}

	// Check if a PR already exists for this branch
	existingPRs, _, err := client.PullRequests.List(ctx, upstreamOwner, repo, &github.PullRequestListOptions{
		Head:  fmt.Sprintf("%s:%s", headOwner, branchName),
		State: "open",
	})
	if err != nil {
		return fmt.Errorf("failed to check for existing PRs: %w", err)
	}

	if len(existingPRs) > 0 {
		pr := existingPRs[0]
		fmt.Printf("Updated existing PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
		return nil
	}

	// Create a PR
	newPR := &github.NewPullRequest{
		Title:               github.Ptr(prTitle),
		Head:                github.Ptr(fmt.Sprintf("%s:%s", headOwner, branchName)),
		Base:                github.Ptr(defaultBranch),
		Body:                github.Ptr(prBody),
		MaintainerCanModify: github.Ptr(true),
	}

	pr, _, err := client.PullRequests.Create(ctx, upstreamOwner, repo, newPR)
	if err != nil {
		return fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return nil
}

// printDiff prints a simple diff between two strings with color
func printDiff(original, updated string) {
	originalLines := strings.Split(original, "\n")
	updatedLines := strings.Split(updated, "\n")

	for i := 0; i < len(originalLines) || i < len(updatedLines); i++ {
		if i >= len(originalLines) {
			// New line added
			fmt.Printf("%s+ %s%s\n", colorGreen, updatedLines[i], colorReset)
		} else if i >= len(updatedLines) {
			// Line removed
			fmt.Printf("%s- %s%s\n", colorRed, originalLines[i], colorReset)
		} else if originalLines[i] != updatedLines[i] {
			// Line changed
			fmt.Printf("%s- %s%s\n", colorRed, originalLines[i], colorReset)
			fmt.Printf("%s+ %s%s\n", colorGreen, updatedLines[i], colorReset)
		} else if strings.Contains(originalLines[i], "uses:") && strings.Contains(originalLines[i], "@") {
			// Show unchanged action lines for context
			fmt.Printf("  %s\n", originalLines[i])
		}
	}
}

// Add new function to get authenticated user
func getAuthenticatedUser(ctx context.Context, client *github.Client) (string, error) {
	user, _, err := client.Users.Get(ctx, "")
	if err != nil {
		return "", err
	}
	return user.GetLogin(), nil
}

// Add new function to wait for fork to be ready
func waitForFork(ctx context.Context, client *github.Client, owner, repo string) error {
	// Try up to 10 times with a 2-second delay
	for i := 0; i < 10; i++ {
		_, resp, err := client.Repositories.Get(ctx, owner, repo)
		if err == nil {
			return nil // Fork is ready
		}
		if resp.StatusCode != 404 {
			return err // Unexpected error
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("fork not ready after waiting")
}

func processDependabotConfig(ctx context.Context, client *github.Client, owner, repo, branch string, dryRun bool, filesChanged map[string]bool) (map[string]bool, error) {

	// Try to get existing file
	content, _, _, err := client.Repositories.GetContents(
		ctx,
		owner,
		repo,
		dependabotPath,
		&github.RepositoryContentGetOptions{Ref: branch},
	)

	defaultConfig := []byte(`version: 2
updates:
   - package-ecosystem: github-actions
     directory: /
     schedule:
        interval: monthly
     groups:
        actions:
           patterns:
              - '*'
`)

	if err != nil {
		if dryRun {
			fmt.Printf("%sWould create new %s with GitHub Actions configuration:%s\n", colorYellow, dependabotPath, colorReset)
			fmt.Printf("%s\n", string(defaultConfig))
			filesChanged[dependabotPath] = true
			return filesChanged, nil
		}

		// Create new file
		_, _, err = client.Repositories.CreateFile(
			ctx,
			owner,
			repo,
			dependabotPath,
			&github.RepositoryContentFileOptions{
				Message: github.Ptr("Add dependabot configuration for GitHub Actions"),
				Content: defaultConfig,
				Branch:  github.Ptr(branch),
			},
		)
		if err != nil {
			return filesChanged, fmt.Errorf("failed to create dependabot config: %w", err)
		}
		logrus.Info("Created new dependabot.yml with GitHub Actions configuration")
		filesChanged[dependabotPath] = true
		return filesChanged, nil
	}

	// File exists, decode content
	fileContent, err := content.GetContent()
	if err != nil {
		return filesChanged, fmt.Errorf("failed to decode content: %w", err)
	}

	// Parse YAML
	var config map[interface{}]interface{}
	if err := yaml.Unmarshal([]byte(fileContent), &config); err != nil {
		return filesChanged, fmt.Errorf("failed to parse yaml: %w", err)
	}

	updates, ok := config["updates"].([]interface{})
	if !ok {
		updates = []interface{}{}
	}

	// Check if GitHub Actions config exists and is properly configured
	hasGitHubActions := false
	for _, update := range updates {
		if u, ok := update.(map[interface{}]interface{}); ok {
			if ecosystem, ok := u["package-ecosystem"].(string); ok {
				if ecosystem == "github-actions" {
					hasGitHubActions = true
					break
				}
			}
		}
	}

	if !hasGitHubActions {
		if dryRun {
			fmt.Printf("%sWould add GitHub Actions configuration to existing %s%s\n", colorYellow, dependabotPath, colorReset)
			filesChanged[dependabotPath] = true
			return filesChanged, nil
		}

		// Add GitHub Actions config
		newUpdate := map[string]interface{}{
			"package-ecosystem": "github-actions",
			"directory":         "/",
			"schedule": map[string]interface{}{
				"interval": "monthly",
			},
			"groups": map[string]interface{}{
				"actions": map[string]interface{}{
					"patterns": []string{"*"},
				},
			},
		}
		updates = append(updates, newUpdate)
		config["updates"] = updates

		// Convert back to YAML
		newContent, err := yaml.Marshal(config)
		if err != nil {
			return filesChanged, fmt.Errorf("failed to marshal yaml: %w", err)
		}

		// Update file
		_, _, err = client.Repositories.UpdateFile(
			ctx,
			owner,
			repo,
			dependabotPath,
			&github.RepositoryContentFileOptions{
				Message: github.Ptr("Add GitHub Actions configuration to dependabot.yml"),
				Content: newContent,
				SHA:     content.SHA,
				Branch:  github.Ptr(branch),
			},
		)
		if err != nil {
			return filesChanged, fmt.Errorf("failed to update dependabot config: %w", err)
		}
		logrus.Info("Added GitHub Actions configuration to existing dependabot.yml")
		filesChanged[dependabotPath] = true
	}

	return filesChanged, nil
}
