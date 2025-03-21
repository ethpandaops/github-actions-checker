package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-github/v70/github"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	inputJSONFile string
	targetRepo    string
	branchName    string
	prTitle       string
	prBody        string
	allRepos      bool
	skipPR        bool
	createPRCmd   = &cobra.Command{
		Use:   "create-pr",
		Short: "Create a PR to update GitHub Actions to use recommended hashes",
		RunE:  createPR,
	}
)

func init() {
	createPRCmd.Flags().StringVarP(&inputJSONFile, "input", "i", "", "Input JSON file with action dependencies")
	createPRCmd.Flags().StringVarP(&targetRepo, "repo", "r", "", "Target repository for PR (format: owner/repo)")
	createPRCmd.Flags().StringVarP(&branchName, "branch", "b", "update-github-actions", "Branch name for the PR")
	createPRCmd.Flags().StringVarP(&prTitle, "title", "t", "Update GitHub Actions to use pinned hashes", "PR title")
	createPRCmd.Flags().StringVarP(&prBody, "body", "", "This PR updates GitHub Actions to use pinned commit hashes for better security.", "PR body")
	createPRCmd.Flags().BoolVarP(&allRepos, "all", "a", false, "Process all repositories in the input file")
	createPRCmd.Flags().BoolVarP(&skipPR, "skip-pr", "s", false, "Skip PR creation, only create branch with changes")
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

	var deps []ActionDependency
	if err := json.Unmarshal(data, &deps); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

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
	return processRepoWithBranch(ctx, client, owner, repo, defaultBranch, branchName, targetDeps)
}

// New function to handle the repository processing with a known branch
func processRepoWithBranch(ctx context.Context, client *github.Client, owner, repo, defaultBranch, branchName string, targetDeps []ActionDependency) error {
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

	// Process each workflow file
	filesChanged := make(map[string]bool)
	for _, dep := range targetDeps {
		workflowPath := dep.Workflow

		// Get the workflow file content
		fileContent, _, _, err := client.Repositories.GetContents(
			ctx, owner, repo, workflowPath,
			&github.RepositoryContentGetOptions{Ref: branchName},
		)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"repo":     targetRepo,
				"workflow": workflowPath,
				"error":    err,
			}).Error("Failed to get workflow file")
			continue
		}

		content, err := fileContent.GetContent()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"repo":     targetRepo,
				"workflow": workflowPath,
				"error":    err,
			}).Error("Failed to decode content")
			continue
		}

		// Update the content with recommended hashes
		updatedContent := content
		changed := false

		// Use regex to handle potential whitespace variations

		type SpecialCase struct {
			Pattern     string
			Replacement string
		}

		specialCases := []SpecialCase{
			{
				Pattern:     `(\s*)uses: nobrayner/discord-webhook@2f38abc8877c7e8d2b0ded0cfd9599632014279f # 2f38abc`,
				Replacement: "${1}uses: nobrayner/discord-webhook@1766a33bf571acdcc0678f00da4fb83aad01ebc7 # v1",
			},
			{
				Pattern:     `(\s*)uses: azure/setup-helm@37dd2562cae2f186a3dc13f2bb5d4abe08dbfec4 # 37dd256`,
				Replacement: "${1}uses: azure/setup-helm@b9e51907a09c216f16ebe8536097933489208112 # v4.3.0",
			},
			{
				Pattern:     `(\s*)uses: crate-ci/typos@0fa392de4a080a8f22469c05415090ee3addf4fb # 0fa392d`,
				Replacement: "${1}uses: crate-ci/typos@7bc041cbb7ca9167c9e0e4ccbb26f48eb0f9d4e0 # v1.30.2",
			},
			{
				Pattern:     `(\s*)uses: crate-ci/typos@d2c5225afeda85a5abf7a567cdd01c3e329c8ccb # d2c5225`,
				Replacement: "${1}uses: crate-ci/typos@7bc041cbb7ca9167c9e0e4ccbb26f48eb0f9d4e0 # v1.30.2",
			},
			{
				Pattern:     `(\s*)uses: asdf-vm/actions/setup@833d04dfd3c702c45fa5cbccffdf17a526d40ed2 # 833d04d`,
				Replacement: "${1}uses: asdf-vm/actions/setup@05e0d2ed97b598bfce82fd30daf324ae0c4570e6 # v3.0.2",
			},
			{
				Pattern:     `(\s*)uses: asdf-vm/actions/setup@7dd2d2ea8a8f52028ca0fdfba65767b8f2db8298 # 7dd2d2e`,
				Replacement: "${1}uses: asdf-vm/actions/setup@05e0d2ed97b598bfce82fd30daf324ae0c4570e6 # v3.0.2",
			},
			{
				Pattern:     `(\s*)uses: jwalton/gh-docker-logs@eb53a99ccbbb34d4243439c2c3dac3ed78a926ed # eb53a99`,
				Replacement: "${1}uses: jwalton/gh-docker-logs@2741064ab9d7af54b0b1ffb6076cf64c16f0220e # v2.2.2",
			},
			{
				Pattern:     `(\s*)uses: nrkno/yaml-schema-validator-github-action@4280780c703671c96fcdf493b2e64b16e25c4941 # 4280780`,
				Replacement: "${1}uses: nrkno/yaml-schema-validator-github-action@54e1fe495e281c451e1ece58808b6fd7710c30ed # v5.1.0",
			},
		}

		for _, specialCase := range specialCases {
			re := regexp.MustCompile(specialCase.Pattern)
			if re.MatchString(updatedContent) {
				updatedContent = re.ReplaceAllString(updatedContent, specialCase.Replacement)
				changed = true
				logrus.WithFields(logrus.Fields{
					"action":   "azure/setup-helm",
					"from":     "37dd2562cae2f186a3dc13f2bb5d4abe08dbfec4",
					"to":       "b9e51907a09c216f16ebe8536097933489208112",
					"workflow": workflowPath,
				}).Info("Updating azure/setup-helm action")
			}
		}

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
						logrus.WithFields(logrus.Fields{
							"action":   action.Name,
							"version":  action.Version,
							"workflow": workflowPath,
						}).Info("Updating version comment for hashed action")
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
					updatedContent = re.ReplaceAllString(updatedContent, replacement)
					changed = true
					logrus.WithFields(logrus.Fields{
						"action":   action.Name,
						"from":     action.Version,
						"to":       action.RecommendedHash,
						"workflow": workflowPath,
					}).Info("Updating action")
				}
			}
		}

		// If changes were made, commit the file
		if changed {
			// Create a commit
			opts := &github.RepositoryContentFileOptions{
				Message: github.Ptr(fmt.Sprintf("Update GitHub Actions in %s to use pinned hashes", dep.Workflow)),
				Content: []byte(updatedContent),
				Branch:  github.Ptr(branchName),
				SHA:     fileContent.SHA,
			}

			_, _, err = client.Repositories.UpdateFile(ctx, owner, repo, workflowPath, opts)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"repo":     targetRepo,
					"workflow": workflowPath,
					"error":    err,
				}).Error("Failed to update file")
				continue
			}

			filesChanged[workflowPath] = true
		}
	}

	// If no files were changed, check if a PR already exists and show its link
	if len(filesChanged) == 0 {
		logrus.Info("No files were changed")

		// Check if a PR already exists for this branch
		existingPRs, _, err := client.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
			Head:  fmt.Sprintf("%s:%s", owner, branchName),
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
		return nil
	}

	// If skipPR flag is set, don't create a PR
	if skipPR {
		fmt.Printf("Changes made to branch '%s' in repo '%s/%s'. PR creation skipped as requested.\n", branchName, owner, repo)
		return nil
	}

	// Check if a PR already exists for this branch
	existingPRs, _, err := client.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		Head:  fmt.Sprintf("%s:%s", owner, branchName),
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
		Head:                github.Ptr(branchName),
		Base:                github.Ptr(defaultBranch),
		Body:                github.Ptr(prBody),
		MaintainerCanModify: github.Ptr(true),
	}

	pr, _, err := client.PullRequests.Create(ctx, owner, repo, newPR)
	if err != nil {
		return fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return nil
}
