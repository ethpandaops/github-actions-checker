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

	"github.com/google/go-github/v70/github"
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
	LogLevel        string
	BranchName      string
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
	rootCmd.Flags().StringVarP(&LogLevel, "log-level", "l", "info", "Set log level (debug, info, warn, error, fatal, panic)")
	rootCmd.Flags().StringVarP(&BranchName, "branch", "b", "", "Specific branch to scan (overrides default branch)")
}

type ActionDependency struct {
	Repo     string          `json:"repo"`
	Actions  []ActionDetails `json:"actions"`
	Workflow string          `json:"workflow"`
	Branch   string          `json:"branch"`
}

// Add new struct for Dependabot info
type DependabotInfo struct {
	Repo          string `json:"repo"`
	FileExists    bool   `json:"fileExists"`
	ActionsUpdate bool   `json:"actionsUpdate"`
	WorkflowCount int    `json:"workflowCount"`
	ActionCount   int    `json:"actionCount"`
}

// Modify the output structure
type OutputData struct {
	Workflows  []ActionDependency `json:"workflows"`
	DependaBot []DependabotInfo   `json:"dependaBot"`
}

type ActionDetails struct {
	Name                                string `json:"name"`
	Version                             string `json:"version"`
	VersionHashReverseLookupVersion     string `json:"version_reverse_lookup,omitempty"`
	Type                                string `json:"type"` // "internal" or "external"
	IsHashedVersion                     bool   `json:"is_hashed_version"`
	RecommendedHash                     string `json:"recommended_hash,omitempty"`
	RecommendedHashReverseLookupVersion string `json:"recommended_hash_reverse_lookup,omitempty"`
}

func run(cmd *cobra.Command, args []string) error {
	// Set log level based on log-level flag or debug flag

	level, err := logrus.ParseLevel(LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	logrus.SetLevel(level)

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("GITHUB_TOKEN environment variable is required")
	}

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	var allDeps []ActionDependency
	var dependabotInfo []DependabotInfo

	if RepoName != "" {
		parts := strings.Split(RepoName, "/")
		if len(parts) != 2 {
			return fmt.Errorf("repo must be in format owner/repo")
		}
		deps := getWorkflowDependencies(ctx, client, parts[0], parts[1])
		allDeps = append(allDeps, deps...)

		// Check for dependabot file
		dInfo := checkDependabotFile(ctx, client, parts[0], parts[1])
		dependabotInfo = append(dependabotInfo, dInfo)
	} else if OrgName != "" {
		opt := &github.RepositoryListByOrgOptions{
			Type: "public",
			ListOptions: github.ListOptions{
				PerPage: 500,
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

				// Check for dependabot file
				dInfo := checkDependabotFile(ctx, client, OrgName, *repo.Name)
				dependabotInfo = append(dependabotInfo, dInfo)
			}

			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	} else {
		return fmt.Errorf("either --org or --repo flag must be specified")
	}

	// Create the new output structure
	outputData := OutputData{
		Workflows:  allDeps,
		DependaBot: dependabotInfo,
	}

	output, err := json.MarshalIndent(outputData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Determine output file name
	outputFile := ""
	if OutputFile != "" {
		outputFile = OutputFile
	} else if RepoName != "" {
		outputFile = strings.ReplaceAll(RepoName, "/", "-")
		// Append branch name if specified
		if BranchName != "" {
			outputFile = fmt.Sprintf("%s-%s", outputFile, BranchName)
		}
	} else if OrgName != "" {
		outputFile = OrgName
		// Append branch name if specified
		if BranchName != "" {
			outputFile = fmt.Sprintf("%s-%s", outputFile, BranchName)
		}
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

	if err := generateHTMLReport(outputPath, htmlOutputPath, outputData, generatedTime); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	fmt.Printf("HTML report generated at %s\n", htmlOutputPath)
	return nil
}

func getWorkflowDependencies(ctx context.Context, client *github.Client, owner, repo string) []ActionDependency {
	var deps []ActionDependency
	// Track processed local actions to avoid infinite recursion
	processedLocalActions := make(map[string]bool)

	// Use specified branch if provided, otherwise get default branch
	branchToUse := BranchName
	if branchToUse == "" {
		repository, resp, err := client.Repositories.Get(ctx, owner, repo)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"repo":  fmt.Sprintf("%s/%s", owner, repo),
				"error": err,
				"resp":  resp.Status,
			}).Error("Failed to get repository default branch. Using 'main' as fallback.")
			// Continue with "main" as fallback
			branchToUse = "main"
		} else {
			branchToUse = *repository.DefaultBranch
		}
	}

	// Helper function to check if a file exists and process it
	var checkAndProcessWorkflow func(path string) ([]ActionDetails, []ActionDependency)
	checkAndProcessWorkflow = func(path string) ([]ActionDetails, []ActionDependency) {
		content, _, resp, err := client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{
			Ref: branchToUse,
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

					// The action doesnt have the filename, so we have to try action.yml / action.yaml
					actionYamlPath = actionYamlPath + ".yml"
					localActions, subDeps := checkAndProcessWorkflow(actionYamlPath)
					if localActions == nil && subDeps == nil || len(localActions) == 0 && len(subDeps) == 0 {
						actionYamlPath = strings.TrimSuffix(actionYamlPath, ".yml") + ".yaml"
						localActions, subDeps = checkAndProcessWorkflow(actionYamlPath)
					}
					if localActions == nil && subDeps == nil || len(localActions) == 0 && len(subDeps) == 0 {
						logrus.WithFields(logrus.Fields{
							"repo": fmt.Sprintf("%s/%s", owner, repo),
							"path": actionPath,
						}).Error("Failed to process local action")
					}

					if localActions != nil {
						localDeps = append(localDeps, ActionDependency{
							Repo:     fmt.Sprintf("%s/%s", owner, repo),
							Actions:  localActions,
							Workflow: actionYamlPath,
							Branch:   branchToUse,
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
	tree, _, err := client.Git.GetTree(ctx, owner, repo, branchToUse, true)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo":   fmt.Sprintf("%s/%s", owner, repo),
			"branch": branchToUse,
			"error":  err,
		}).Error("Failed to get git tree")
		return deps
	}

	for _, entry := range tree.Entries {
		// Process GitHub workflow files
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
					Workflow: entry.GetPath(),
					Branch:   branchToUse,
				})
				deps = append(deps, localDeps...)
			}
		}

		// Also process root level action.yml or action.yaml files
		if entry.GetPath() == "action.yml" || entry.GetPath() == "action.yaml" {
			logrus.WithFields(logrus.Fields{
				"repo":     fmt.Sprintf("%s/%s", owner, repo),
				"workflow": entry.GetPath(),
			}).Info("Processing root action file")

			actions, localDeps := checkAndProcessWorkflow(entry.GetPath())
			if len(actions) > 0 {
				logrus.WithFields(logrus.Fields{
					"repo":         fmt.Sprintf("%s/%s", owner, repo),
					"workflow":     entry.GetPath(),
					"action_count": len(actions),
				}).Info("Found actions in root action file")
				deps = append(deps, ActionDependency{
					Repo:     fmt.Sprintf("%s/%s", owner, repo),
					Actions:  actions,
					Workflow: entry.GetPath(),
					Branch:   branchToUse,
				})
				deps = append(deps, localDeps...)
			}
		}

		// Process action.yml or action.yaml files in .github directory and subdirectories
		if strings.HasPrefix(entry.GetPath(), ".github/") &&
			!strings.HasPrefix(entry.GetPath(), ".github/workflows/") &&
			(strings.HasSuffix(entry.GetPath(), "/action.yml") ||
				strings.HasSuffix(entry.GetPath(), "/action.yaml") ||
				entry.GetPath() == ".github/action.yml" ||
				entry.GetPath() == ".github/action.yaml") {

			logrus.WithFields(logrus.Fields{
				"repo":     fmt.Sprintf("%s/%s", owner, repo),
				"workflow": entry.GetPath(),
			}).Info("Processing .github directory action file")

			actions, localDeps := checkAndProcessWorkflow(entry.GetPath())
			if len(actions) > 0 {
				logrus.WithFields(logrus.Fields{
					"repo":         fmt.Sprintf("%s/%s", owner, repo),
					"workflow":     entry.GetPath(),
					"action_count": len(actions),
				}).Info("Found actions in .github directory action file")
				deps = append(deps, ActionDependency{
					Repo:     fmt.Sprintf("%s/%s", owner, repo),
					Actions:  actions,
					Workflow: entry.GetPath(),
					Branch:   branchToUse,
				})
				deps = append(deps, localDeps...)
			}
		}
	}

	// Update all ActionDependency instances to include the branch
	for i := range deps {
		deps[i].Branch = branchToUse
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
		// Verify the commit exists
		commit, _, commitErr := client.Repositories.GetCommit(ctx, owner, repo, reference.Object.GetSHA(), nil)
		if commitErr == nil && commit != nil && commit.SHA != nil {
			return *commit.SHA, nil
		}
	}

	// If that fails, try to get it as a tag
	reference, _, err = client.Git.GetRef(ctx, owner, repo, "refs/tags/"+ref)
	if err == nil && reference != nil && reference.Object != nil {
		// For annotated tags, we need to resolve the tag object to get the actual commit
		if reference.Object.GetType() == "tag" {
			tag, _, tagErr := client.Git.GetTag(ctx, owner, repo, reference.Object.GetSHA())
			if tagErr == nil && tag != nil && tag.Object != nil {
				return tag.Object.GetSHA(), nil
			}
		}

		// Verify the commit exists
		commit, _, commitErr := client.Repositories.GetCommit(ctx, owner, repo, reference.Object.GetSHA(), nil)
		if commitErr == nil && commit != nil && commit.SHA != nil {
			return *commit.SHA, nil
		}
	}

	// If that fails, try to get it as a branch
	reference, _, err = client.Git.GetRef(ctx, owner, repo, "refs/heads/"+ref)
	if err == nil && reference != nil && reference.Object != nil {
		// Verify the commit exists
		commit, _, commitErr := client.Repositories.GetCommit(ctx, owner, repo, reference.Object.GetSHA(), nil)
		if commitErr == nil && commit != nil && commit.SHA != nil {
			return *commit.SHA, nil
		}
	}

	// As a last resort, try to get the commit directly
	commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, ref, nil)
	if err == nil && commit != nil && commit.SHA != nil {
		return *commit.SHA, nil
	}

	return "", fmt.Errorf("could not find valid commit hash for ref %s", ref)
}

// New function to get human-readable version for a commit hash
func getHumanReadableVersion(ctx context.Context, client *github.Client, owner, repo, commitHash string) string {
	// Try to find a tag pointing to this commit
	tags, _, err := client.Repositories.ListTags(ctx, owner, repo, &github.ListOptions{PerPage: 500})
	if err == nil {
		for _, tag := range tags {
			if tag.Commit != nil && tag.Commit.SHA != nil && *tag.Commit.SHA == commitHash {
				return *tag.Name
			}
		}
	}

	// If no tag found, try to find the branch and use short hash
	branches, _, err := client.Repositories.ListBranches(ctx, owner, repo, &github.BranchListOptions{ListOptions: github.ListOptions{PerPage: 500}})
	if err == nil {
		for _, branch := range branches {
			if branch.Commit != nil && branch.Commit.SHA != nil {
				// Get the commit to check if it's in the branch history
				commit, _, err := client.Repositories.GetCommit(ctx, owner, repo, commitHash, &github.ListOptions{})
				if err == nil && commit != nil && branch.Name != nil {
					// Return branch name + short hash
					shortHash := commitHash
					if len(shortHash) > 7 {
						shortHash = shortHash[:7]
					}
					return fmt.Sprintf("%s-%s", *branch.Name, shortHash)
				}
			}
		}
	}

	// If all else fails, just return the short hash
	if len(commitHash) > 7 {
		return commitHash[:7]
	}
	return commitHash
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

			// Strip quotes from name if present
			name = strings.Trim(name, `"'`)

			// Only consider actions starting with ./ as internal
			actionType := "external"
			if strings.HasPrefix(name, "./") {
				actionType = "internal"
			}

			// Check if version is a commit hash (40 character hex string)
			isHashed := false
			recommendedHash := ""
			hashReverseLookupVersion := ""
			recommendedHashReverseLookupVersion := ""
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

						// Get human-readable version for the hash
						if strings.Contains(name, "/") {
							parts := strings.Split(name, "/")
							if len(parts) >= 2 {
								actionOwner := parts[0]
								actionRepo := parts[1]

								ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
								defer cancel()

								ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: os.Getenv("GITHUB_TOKEN")})
								tc := oauth2.NewClient(ctx, ts)
								client := github.NewClient(tc)

								hashReverseLookupVersion = getHumanReadableVersion(ctx, client, actionOwner, actionRepo, versionTrimmed)
							}
						}
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

							logrus.WithFields(logrus.Fields{
								"action":  name,
								"version": versionTrimmed,
							}).Debug("Getting commit hash for version")

							hash, err := getCommitHashForRef(ctx, client, actionOwner, actionRepo, versionTrimmed)
							if err == nil {
								recommendedHash = hash
								recommendedHashReverseLookupVersion = getHumanReadableVersion(ctx, client, actionOwner, actionRepo, recommendedHash)
								logrus.WithFields(logrus.Fields{
									"action":                 name,
									"version":                versionTrimmed,
									"hash":                   hash,
									"human_readable_version": recommendedHashReverseLookupVersion,
								}).Debug("Got commit hash for version")
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
				Name:                                name,
				Version:                             version,
				VersionHashReverseLookupVersion:     hashReverseLookupVersion,
				Type:                                actionType,
				IsHashedVersion:                     isHashed,
				RecommendedHash:                     recommendedHash,
				RecommendedHashReverseLookupVersion: recommendedHashReverseLookupVersion,
			})
		}
	}

	return actions
}

func checkDependabotFile(ctx context.Context, client *github.Client, owner, repo string) DependabotInfo {
	result := DependabotInfo{
		Repo:          fmt.Sprintf("%s/%s", owner, repo),
		FileExists:    false,
		ActionsUpdate: false,
		WorkflowCount: 0,
		ActionCount:   0,
	}

	// Try to get the dependabot.yml file
	content, _, resp, err := client.Repositories.GetContents(
		ctx,
		owner,
		repo,
		".github/dependabot.yml",
		&github.RepositoryContentGetOptions{},
	)

	// Check if file wasn't found
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
			// Try dependabot.yaml as an alternative
			content, _, resp, err = client.Repositories.GetContents(
				ctx,
				owner,
				repo,
				".github/dependabot.yaml",
				&github.RepositoryContentGetOptions{},
			)

			if err != nil {
				// File doesn't exist or other error
				return result
			}
		} else {
			// Some other error occurred
			logrus.WithFields(logrus.Fields{
				"repo":  fmt.Sprintf("%s/%s", owner, repo),
				"error": err,
			}).Debug("Error checking for dependabot file")
			return result
		}
	}

	// File exists
	result.FileExists = true

	// Get the content
	decodedContent, err := content.GetContent()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"repo":  fmt.Sprintf("%s/%s", owner, repo),
			"error": err,
		}).Debug("Failed to decode dependabot.yml content")
		return result
	}

	// Check if github-actions is enabled
	if strings.Contains(decodedContent, "package-ecosystem: github-actions") {
		result.ActionsUpdate = true
	}

	return result
}
