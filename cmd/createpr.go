package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-github/v60/github"
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
	createPRCmd.MarkFlagRequired("input")
	createPRCmd.MarkFlagRequired("repo")
	rootCmd.AddCommand(createPRCmd)
}

func createPR(cmd *cobra.Command, args []string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	// Parse target repo
	parts := strings.Split(targetRepo, "/")
	if len(parts) != 2 {
		return fmt.Errorf("repo must be in format owner/repo")
	}
	owner, repo := parts[0], parts[1]

	// Read and parse the JSON file
	data, err := os.ReadFile(inputJSONFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var deps []ActionDependency
	if err := json.Unmarshal(data, &deps); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

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
	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return fmt.Errorf("failed to get repository: %w", err)
	}
	defaultBranch := repository.GetDefaultBranch()

	// Get the reference to the default branch
	ref, _, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+defaultBranch)
	if err != nil {
		return fmt.Errorf("failed to get reference: %w", err)
	}

	// Create a new branch
	newRef := &github.Reference{
		Ref:    github.String("refs/heads/" + branchName),
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
		workflowPath := filepath.Join(".github/workflows", dep.Workflow)

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

		for _, action := range dep.Actions {
			if action.Type == "external" && !action.IsHashedVersion && action.RecommendedHash != "" {
				// Create a pattern to match the action reference
				pattern := fmt.Sprintf(`uses:\s+%s@%s\b`, regexp.QuoteMeta(action.Name), regexp.QuoteMeta(action.Version))
				replacement := fmt.Sprintf("uses: %s@%s # %s", action.Name, action.RecommendedHash, action.Version)

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
				Message: github.String(fmt.Sprintf("Update GitHub Actions in %s to use pinned hashes", dep.Workflow)),
				Content: []byte(updatedContent),
				Branch:  github.String(branchName),
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

	// If no files were changed, exit
	if len(filesChanged) == 0 {
		logrus.Info("No files were changed, skipping PR creation")
		return nil
	}

	// Create a PR
	newPR := &github.NewPullRequest{
		Title:               github.String(prTitle),
		Head:                github.String(branchName),
		Base:                github.String(defaultBranch),
		Body:                github.String(prBody),
		MaintainerCanModify: github.Bool(true),
	}

	pr, _, err := client.PullRequests.Create(ctx, owner, repo, newPR)
	if err != nil {
		return fmt.Errorf("failed to create PR: %w", err)
	}

	fmt.Printf("Created PR #%d: %s\n", pr.GetNumber(), pr.GetHTMLURL())
	return nil
}
