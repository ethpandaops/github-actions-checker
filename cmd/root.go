package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v60/github"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	OrgName         string
	RepoName        string
	OutputDir       string
	OutputFile      string
	IncludeArchived bool
	IncludeForked   bool
	rootCmd         = &cobra.Command{
		Use:   "action-deps",
		Short: "Analyze GitHub Action dependencies in an organization or repository",
		RunE:  run,
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&OrgName, "org", "o", "", "GitHub organization name")
	rootCmd.Flags().StringVarP(&RepoName, "repo", "r", "", "Specific repository to scan (format: owner/repo)")
	rootCmd.Flags().StringVarP(&OutputDir, "output-dir", "d", "reports", "Directory to write output files to")
	rootCmd.Flags().StringVarP(&OutputFile, "output-file", "f", "", "Output file name (without extension)")
	rootCmd.Flags().BoolVarP(&IncludeArchived, "include-archived", "a", false, "Include archived repositories in scan")
	rootCmd.Flags().BoolVarP(&IncludeForked, "include-forked", "", false, "Include forked repositories in scan")
}

type ActionDependency struct {
	Repo     string          `json:"repo"`
	Actions  []ActionDetails `json:"actions"`
	Workflow string          `json:"workflow"`
	Branch   string          `json:"branch"`
}

type ActionDetails struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	Type            string `json:"type"` // "internal" or "external"
	IsHashedVersion bool   `json:"is_hashed_version"`
	RecommendedHash string `json:"recommended_hash,omitempty"`
}

func run(cmd *cobra.Command, args []string) error {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	var allDeps []ActionDependency

	if RepoName != "" {
		parts := strings.Split(RepoName, "/")
		if len(parts) != 2 {
			return fmt.Errorf("repo must be in format owner/repo")
		}
		deps := getWorkflowDependencies(ctx, client, parts[0], parts[1])
		allDeps = append(allDeps, deps...)
	} else if OrgName != "" {
		opt := &github.RepositoryListByOrgOptions{
			Type: "public",
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		}

		if IncludeForked {
			opt.Type = "all"
		}

		for {
			repos, resp, err := client.Repositories.ListByOrg(ctx, OrgName, opt)
			if err != nil {
				return fmt.Errorf("failed to list repositories: %w", err)
			}

			for _, repo := range repos {
				// Skip archived repositories unless explicitly included
				if *repo.Archived && !IncludeArchived {
					logrus.WithFields(logrus.Fields{
						"repo": fmt.Sprintf("%s/%s", OrgName, *repo.Name),
					}).Info("Skipping archived repository")
					continue
				}

				// Skip forked repositories unless explicitly included
				if *repo.Fork && !IncludeForked {
					logrus.WithFields(logrus.Fields{
						"repo": fmt.Sprintf("%s/%s", OrgName, *repo.Name),
					}).Info("Skipping forked repository")
					continue
				}

				logrus.WithFields(logrus.Fields{
					"repo": fmt.Sprintf("%s/%s", OrgName, *repo.Name),
				}).Info("Processing repository")
				deps := getWorkflowDependencies(ctx, client, OrgName, *repo.Name)
				allDeps = append(allDeps, deps...)
			}

			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	} else {
		return fmt.Errorf("either --org or --repo flag must be specified")
	}

	output, err := json.MarshalIndent(allDeps, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Determine output file name
	outputFile := ""
	if OutputFile != "" {
		outputFile = OutputFile
	} else if RepoName != "" {
		outputFile = strings.ReplaceAll(RepoName, "/", "-")
	} else if OrgName != "" {
		outputFile = OrgName
	}

	jsonOutputFile := fmt.Sprintf("%s.json", outputFile)

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	outputPath := filepath.Join(OutputDir, jsonOutputFile)
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	fmt.Printf("Results written to %s\n", outputPath)

	// Generate HTML report automatically
	htmlOutputFile := strings.TrimSuffix(jsonOutputFile, ".json") + ".html"
	htmlOutputPath := filepath.Join(OutputDir, htmlOutputFile)

	// Format the current time as a string
	generatedTime := time.Now().Format("Jan 02, 2006 15:04:05")

	if err := generateHTMLReport(outputPath, htmlOutputPath, allDeps, generatedTime); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	fmt.Printf("HTML report generated at %s\n", htmlOutputPath)
	return nil
}

func getWorkflowDependencies(ctx context.Context, client *github.Client, owner, repo string) []ActionDependency {
	var deps []ActionDependency
	// Track processed local actions to avoid infinite recursion
	processedLocalActions := make(map[string]bool)

	repository, _, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo":  fmt.Sprintf("%s/%s", owner, repo),
			"error": err,
		}).Error("Failed to get repository")
		return deps
	}
	defaultBranch := repository.GetDefaultBranch()

	// Helper function to check if a file exists and process it
	var checkAndProcessWorkflow func(path string) ([]ActionDetails, []ActionDependency)
	checkAndProcessWorkflow = func(path string) ([]ActionDetails, []ActionDependency) {
		content, _, resp, err := client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{
			Ref: defaultBranch,
		})

		if err != nil {
			if resp != nil && resp.StatusCode == 404 {
				// File doesn't exist, return silently
				return nil, nil
			}
			logrus.WithFields(logrus.Fields{
				"repo":  fmt.Sprintf("%s/%s", owner, repo),
				"path":  path,
				"error": err,
			}).Error("Failed to get content")
			return nil, nil
		}

		decodedContent, err := content.GetContent()
		if err != nil || decodedContent == "" {
			logrus.WithFields(logrus.Fields{
				"repo":  fmt.Sprintf("%s/%s", owner, repo),
				"path":  path,
				"error": err,
			}).Error("Failed to decode content")
			return nil, nil
		}

		// Define processWorkflow before using it
		var processWorkflow func(content, path string) ([]ActionDetails, []ActionDependency)
		processWorkflow = func(content, path string) ([]ActionDetails, []ActionDependency) {
			var localDeps []ActionDependency

			actions := extractActions(content)

			// Process local action dependencies
			for _, action := range actions {
				if action.Type == "internal" {
					actionPath := strings.TrimPrefix(action.Name, "./")
					if processedLocalActions[actionPath] {
						continue
					}
					processedLocalActions[actionPath] = true

					actionYamlPath := actionPath
					// Check if action.Name already ends with .yaml or .yml
					if !strings.HasSuffix(action.Name, ".yaml") && !strings.HasSuffix(action.Name, ".yml") {
						actionYamlPath = filepath.Join(actionPath, "action")
					}

					// Try action.yml first
					localActions, subDeps := checkAndProcessWorkflow(actionYamlPath + ".yml")
					if localActions == nil && subDeps == nil {
						localActions, subDeps = checkAndProcessWorkflow(actionYamlPath + ".yaml")
					}

					if localActions != nil {
						localDeps = append(localDeps, ActionDependency{
							Repo:     fmt.Sprintf("%s/%s", owner, repo),
							Actions:  localActions,
							Workflow: actionYamlPath,
							Branch:   defaultBranch,
						})
						localDeps = append(localDeps, subDeps...)
					}
				}
			}

			return actions, localDeps
		}

		return processWorkflow(decodedContent, path)
	}

	// Get all workflow files using the Git Trees API
	tree, _, err := client.Git.GetTree(ctx, owner, repo, defaultBranch, true)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo":  fmt.Sprintf("%s/%s", owner, repo),
			"error": err,
		}).Error("Failed to get git tree")
		return deps
	}

	for _, entry := range tree.Entries {
		if strings.HasPrefix(entry.GetPath(), ".github/workflows/") && isWorkflowFile(entry.GetPath()) {
			logrus.WithFields(logrus.Fields{
				"repo":     fmt.Sprintf("%s/%s", owner, repo),
				"workflow": entry.GetPath(),
			}).Info("Processing workflow file")

			actions, localDeps := checkAndProcessWorkflow(entry.GetPath())
			if len(actions) > 0 {
				logrus.WithFields(logrus.Fields{
					"repo":         fmt.Sprintf("%s/%s", owner, repo),
					"workflow":     entry.GetPath(),
					"action_count": len(actions),
				}).Info("Found actions in workflow")
				deps = append(deps, ActionDependency{
					Repo:     fmt.Sprintf("%s/%s", owner, repo),
					Actions:  actions,
					Workflow: filepath.Base(entry.GetPath()),
					Branch:   defaultBranch,
				})
				deps = append(deps, localDeps...)
			}
		}
	}

	return deps
}

func isWorkflowFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yml" || ext == ".yaml"
}

func getCommitHashForRef(ctx context.Context, client *github.Client, owner, repo, ref string) (string, error) {
	// First try to get the reference directly
	reference, _, err := client.Git.GetRef(ctx, owner, repo, "refs/"+ref)
	if err == nil && reference != nil && reference.Object != nil {
		return reference.Object.GetSHA(), nil
	}

	// If that fails, try to get it as a tag
	reference, _, err = client.Git.GetRef(ctx, owner, repo, "refs/tags/"+ref)
	if err == nil && reference != nil && reference.Object != nil {
		return reference.Object.GetSHA(), nil
	}

	// If that fails, try to get it as a branch
	reference, _, err = client.Git.GetRef(ctx, owner, repo, "refs/heads/"+ref)
	if err == nil && reference != nil && reference.Object != nil {
		return reference.Object.GetSHA(), nil
	}

	return "", fmt.Errorf("could not find commit hash for ref %s", ref)
}

func extractActions(content string) []ActionDetails {
	var actions []ActionDetails
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "uses:") {
			parts := strings.SplitN(line, "uses:", 2)
			if len(parts) != 2 {
				continue
			}
			action := strings.TrimSpace(parts[1])

			// Remove any trailing comments
			if idx := strings.Index(action, "#"); idx != -1 {
				action = strings.TrimSpace(action[:idx])
			}

			name := action
			version := ""
			if idx := strings.Index(action, "@"); idx != -1 {
				name = action[:idx]
				version = action[idx+1:]
			}

			// Only consider actions starting with ./ as internal
			actionType := "external"
			if strings.HasPrefix(name, "./") {
				actionType = "internal"
			}

			// Check if version is a commit hash (40 character hex string)
			isHashed := false
			recommendedHash := ""
			if actionType == "external" && version != "" {
				// Strip comments from version
				versionTrimmed := version
				if idx := strings.Index(version, "#"); idx != -1 {
					versionTrimmed = strings.TrimSpace(version[:idx])
				}

				if len(versionTrimmed) == 40 {
					if _, err := hex.DecodeString(versionTrimmed); err == nil {
						isHashed = true
						recommendedHash = versionTrimmed
					}
				} else {
					// Get commit hash from remote repository depending on the version
					if strings.Contains(name, "/") {
						parts := strings.Split(name, "/")
						if len(parts) >= 2 {
							// For GitHub actions, the format is typically owner/repo
							actionOwner := parts[0]
							actionRepo := parts[1]

							// Create a background context with timeout for this operation
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							defer cancel()

							// Get the GitHub client from the parent function's context
							ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")})
							tc := oauth2.NewClient(ctx, ts)
							client := github.NewClient(tc)

							hash, err := getCommitHashForRef(ctx, client, actionOwner, actionRepo, versionTrimmed)
							if err == nil {
								recommendedHash = hash
							} else {
								logrus.WithFields(logrus.Fields{
									"action":  name,
									"version": versionTrimmed,
									"error":   err,
								}).Debug("Failed to get commit hash for version")
							}
						}
					}
				}
			}

			actions = append(actions, ActionDetails{
				Name:            name,
				Version:         version,
				Type:            actionType,
				IsHashedVersion: isHashed,
				RecommendedHash: recommendedHash,
			})
		}
	}

	return actions
}
