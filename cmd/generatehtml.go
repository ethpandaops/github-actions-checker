package cmd

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var (
	inputFile string
	reportCmd = &cobra.Command{
		Use:   "generate-html",
		Short: "Generate HTML report from actions JSON file",
		RunE:  generateHTMLFromJson,
	}
)

func init() {
	reportCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input JSON file")
	reportCmd.Flags().StringVarP(&OutputDir, "output-dir", "d", "reports", "Directory to write output files to")
	rootCmd.AddCommand(reportCmd)
}

type RepoSummary struct {
	Name        string
	Workflows   []WorkflowSummary
	HasWarnings bool
}

type WorkflowSummary struct {
	Name    string
	Actions []ActionDetails
	Branch  string
}

func generateHTMLFromJson(cmd *cobra.Command, args []string) error {
	if inputFile == "" {
		return fmt.Errorf("input file is required")
	}

	// Get file info to extract timestamp
	fileInfo, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	generatedTime := fileInfo.ModTime().Format("Jan 02, 2006 15:04:05")

	// Read JSON file
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var outputData OutputData
	if err := json.Unmarshal(data, &outputData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate HTML report
	outputFile := strings.TrimSuffix(filepath.Base(inputFile), ".json") + ".html"
	outputPath := filepath.Join(OutputDir, outputFile)

	if err := generateHTMLReport(inputFile, outputPath, outputData, generatedTime); err != nil {
		return err
	}

	fmt.Printf("Report generated at %s\n", outputPath)
	return nil
}

// Create a shared function for HTML report generation
func generateHTMLReport(jsonFilePath, outputPath string, data OutputData, generatedTime string) error {
	// Calculate workflow and action counts for each repository
	repoWorkflowsMap := make(map[string]map[string]bool) // repo -> workflow -> exists
	repoActionCountMap := make(map[string]int)           // repo -> action count

	for _, dep := range data.Workflows {
		if _, exists := repoWorkflowsMap[dep.Repo]; !exists {
			repoWorkflowsMap[dep.Repo] = make(map[string]bool)
		}
		repoWorkflowsMap[dep.Repo][dep.Workflow] = true
		repoActionCountMap[dep.Repo] += len(dep.Actions)
	}

	// Update dependabotInfo with workflow and action counts
	for i, info := range data.DependaBot {
		if workflows, exists := repoWorkflowsMap[info.Repo]; exists {
			data.DependaBot[i].WorkflowCount = len(workflows)
			data.DependaBot[i].ActionCount = repoActionCountMap[info.Repo]
		}
	}

	// Calculate statistics
	var externalWithHash, externalWithoutHash int

	// Track external actions usage
	actionUsage := make(map[string]map[string]int) // action name -> version -> count

	for _, dep := range data.Workflows {
		for _, action := range dep.Actions {
			if action.Type == "external" {
				if action.IsHashedVersion {
					externalWithHash++
				} else {
					externalWithoutHash++
				}

				// Track action usage
				if _, exists := actionUsage[action.Name]; !exists {
					actionUsage[action.Name] = make(map[string]int)
				}
				actionUsage[action.Name][action.Version]++
			}
		}
	}

	// Convert action usage map to a sorted slice for the template
	type ActionVersionUsage struct {
		Version              string
		HumanReadableVersion string
		Count                int
	}

	type ActionUsageSummary struct {
		Name     string
		Versions []ActionVersionUsage
		Count    int
	}

	actionSummaries := make([]ActionUsageSummary, 0, len(actionUsage))
	for name, versions := range actionUsage {
		totalCount := 0
		versionUsages := make([]ActionVersionUsage, 0, len(versions))

		// Find human-readable versions for each hash
		versionToHumanReadable := make(map[string]string)
		for _, dep := range data.Workflows {
			for _, action := range dep.Actions {
				if action.Name == name && action.VersionHashReverseLookupVersion != "" {
					versionToHumanReadable[action.Version] = action.VersionHashReverseLookupVersion
				}
			}
		}

		for version, count := range versions {
			versionUsages = append(versionUsages, ActionVersionUsage{
				Version:              version,
				HumanReadableVersion: versionToHumanReadable[version],
				Count:                count,
			})
			totalCount += count
		}

		// Sort versions by usage count (descending)
		sort.Slice(versionUsages, func(i, j int) bool {
			return versionUsages[i].Count > versionUsages[j].Count
		})

		actionSummaries = append(actionSummaries, ActionUsageSummary{
			Name:     name,
			Versions: versionUsages,
			Count:    totalCount,
		})
	}

	// Sort actions by total usage count (descending)
	sort.Slice(actionSummaries, func(i, j int) bool {
		return actionSummaries[i].Count > actionSummaries[j].Count
	})

	// Organize data by repository
	repoMap := make(map[string]*RepoSummary)
	for _, dep := range data.Workflows {
		if _, exists := repoMap[dep.Repo]; !exists {
			repoMap[dep.Repo] = &RepoSummary{
				Name:      dep.Repo,
				Workflows: []WorkflowSummary{},
			}
		}
		repoMap[dep.Repo].Workflows = append(repoMap[dep.Repo].Workflows, WorkflowSummary{
			Name:    dep.Workflow,
			Actions: dep.Actions,
			Branch:  dep.Branch,
		})
	}

	// Convert map to sorted slice and check for warnings
	repos := make([]*RepoSummary, 0, len(repoMap))
	var reposWithWarnings, reposWithoutWarnings int

	for _, repo := range repoMap {
		// Sort workflows by name
		sort.Slice(repo.Workflows, func(i, j int) bool {
			return repo.Workflows[i].Name < repo.Workflows[j].Name
		})

		// Check if repo has any warnings (external deps without hash)
		hasWarnings := false
		for _, workflow := range repo.Workflows {
			for _, action := range workflow.Actions {
				if action.Type == "external" && !action.IsHashedVersion {
					hasWarnings = true
					break
				}
			}
			if hasWarnings {
				break
			}
		}

		// Count repos with/without warnings
		if hasWarnings {
			reposWithWarnings++
		} else {
			reposWithoutWarnings++
		}

		// Add hasWarnings field to the repo summary
		repos = append(repos, &RepoSummary{
			Name:        repo.Name,
			Workflows:   repo.Workflows,
			HasWarnings: hasWarnings,
		})
	}
	sort.Slice(repos, func(i, j int) bool {
		// Sort by warnings first (repos with warnings come first), then by name
		if repos[i].HasWarnings != repos[j].HasWarnings {
			return repos[i].HasWarnings // true comes before false
		}
		return repos[i].Name < repos[j].Name
	})

	// Read the JSON data for embedding in the report
	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %w", err)
	}

	// Create template with custom functions
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}

	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(reportTemplate))

	// Generate HTML report
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	embedData := []byte(fmt.Sprintf(`
	const reportData = %s;
	`, string(jsonData)))

	if err := tmpl.Execute(f, struct {
		Repos                []*RepoSummary
		ActionSummaries      []ActionUsageSummary
		JSONData             template.JS
		InputFile            string
		ExternalWithHash     int
		ExternalWithoutHash  int
		ReposWithWarnings    int
		ReposWithoutWarnings int
		TotalRepos           int
		GeneratedTime        string
		DependabotInfo       []DependabotInfo
	}{
		Repos:                repos,
		ActionSummaries:      actionSummaries,
		JSONData:             template.JS(embedData),
		InputFile:            filepath.Base(jsonFilePath),
		ExternalWithHash:     externalWithHash,
		ExternalWithoutHash:  externalWithoutHash,
		ReposWithWarnings:    reposWithWarnings,
		ReposWithoutWarnings: reposWithoutWarnings,
		TotalRepos:           len(repos),
		GeneratedTime:        generatedTime,
		DependabotInfo:       data.DependaBot,
	}); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	return nil
}

const reportTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Actions Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
        }
        .expanded .collapsible-content {
            max-height: 10000px; /* Large enough to contain content */
        }
        .chevron {
            transition: transform 0.3s;
        }
        .expanded .chevron {
            transform: rotate(90deg);
        }
    </style>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold">GitHub Actions Report</h1>
            <div class="text-right">
								<div class="text-gray-600">{{.GeneratedTime}}</div>
                <div class="text-gray-600">Generated by: <a href="https://github.com/ethpandaops/github-actions-checker" target="_blank" class="text-blue-600 hover:text-blue-800">github-actions-checker</a></div>
            </div>
        </div>

        <!-- Summary Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4">Summary</h2>
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="bg-blue-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-blue-700">{{.TotalRepos}}</div>
                    <div class="text-sm text-blue-600">Total repositories</div>
                </div>
                <div class="bg-red-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-red-700">{{.ReposWithWarnings}}</div>
                    <div class="text-sm text-red-600">Repositories with warnings</div>
                </div>
                <div class="bg-green-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-green-700">{{.ReposWithoutWarnings}}</div>
                    <div class="text-sm text-green-600">Repositories without warnings</div>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-gray-700">{{.ExternalWithoutHash}}/{{add .ExternalWithHash .ExternalWithoutHash}}</div>
                    <div class="text-sm text-gray-600">GitHub Actions without pinned commit version</div>
                </div>
            </div>

            <!-- New Dependabot Summary Section -->
            <div class="mt-6">
                <h3 class="text-lg font-semibold mb-3">Dependabot Status</h3>
                <div class="overflow-x-auto">
                    <table class="min-w-full">
                        <thead>
                            <tr class="bg-gray-50">
                                <th class="px-4 py-2 text-left text-sm font-medium text-gray-500">Repository</th>
                                <th class="px-4 py-2 text-center text-sm font-medium text-gray-500">Dependabot File</th>
                                <th class="px-4 py-2 text-center text-sm font-medium text-gray-500">GitHub Actions Updates</th>
                                <th class="px-4 py-2 text-center text-sm font-medium text-gray-500">Workflows</th>
                                <th class="px-4 py-2 text-center text-sm font-medium text-gray-500">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            {{range .DependabotInfo}}
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-2 text-sm">
                                    <a href="https://github.com/{{.Repo}}" target="_blank" class="text-blue-600 hover:text-blue-800">
                                        {{.Repo}}
                                    </a>
                                </td>
                                <td class="px-4 py-2 text-sm text-center">
                                    {{if .FileExists}}
                                        <span class="text-green-500">✓</span>
                                    {{else}}
                                        <span class="text-red-500">✗</span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-2 text-sm text-center">
                                    {{if .ActionsUpdate}}
                                        <span class="text-green-500">✓</span>
                                    {{else}}
                                        <span class="text-red-500">✗</span>
                                    {{end}}
                                </td>
                                <td class="px-4 py-2 text-sm text-center">
                                    {{.WorkflowCount}}
                                </td>
                                <td class="px-4 py-2 text-sm text-center">
                                    {{.ActionCount}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="mt-4 flex justify-end">
                <button id="expandAllBtn" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-md text-sm font-medium transition-colors">
                    Expand All
                </button>
            </div>
        </div>

        <!-- Actions Usage Summary Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6 collapsible-section expanded">
            <div class="flex justify-between items-center cursor-pointer" onclick="toggleCollapse(this.parentElement)">
                <h2 class="text-xl font-semibold">Actions usage summary</h2>
                <svg class="chevron w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                </svg>
            </div>
            <div class="collapsible-content">
                <div class="mt-4 overflow-x-auto">
                    <table class="min-w-full">
                        <thead>
                            <tr class="bg-gray-50">
                                <th class="px-4 py-2 text-left text-sm font-medium text-gray-500">Action</th>
                                <th class="px-4 py-2 text-center text-sm font-medium text-gray-500 w-24">Total Usage</th>
                                <th class="px-4 py-2 text-right text-sm font-medium text-gray-500 w-64">Versions (Usage Count)</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            {{range .ActionSummaries}}
                            <tr class="hover:bg-gray-50">
                                <td class="px-4 py-2 text-sm">
                                    <a href="https://github.com/{{.Name}}"
                                       target="_blank"
                                       class="text-blue-600 hover:text-blue-800">
                                        {{.Name}}
                                    </a>
                                </td>
                                <td class="px-4 py-2 text-sm text-center font-semibold">{{.Count}}</td>
                                <td class="px-4 py-2 text-sm">
                                    <div class="space-y-1">
																		{{$actionName := .Name}}
                                        {{range .Versions}}
                                        <div class="px-2 py-1 {{if not (eq (len .Version) 40)}}bg-red-100{{else}}bg-blue-50{{end}} rounded text-xs flex items-center">
                                            <span class="font-mono">
																								<a href="https://github.com/{{$actionName}}/commit/{{.Version}}" target="_blank" class="text-blue-600 hover:text-blue-800">{{.Version}}</a>
																						</span>
                                            {{if .HumanReadableVersion}}
                                                <span class="ml-2 text-gray-600">[{{.HumanReadableVersion}}]</span>
                                            {{end}}
                                            <span class="ml-auto font-semibold">{{.Count}}</span>
                                        </div>
                                        {{end}}
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="space-y-6">
            {{range .Repos}}
            <div class="bg-white rounded-lg shadow-md p-6 collapsible-section {{if .HasWarnings}}expanded{{end}}">
                <div class="flex justify-between items-center cursor-pointer" onclick="toggleCollapse(this.parentElement)">
                    <h2 class="text-xl font-semibold">
                        <a href="https://github.com/{{.Name}}" target="_blank" class="text-blue-600 hover:text-blue-800">
                            {{.Name}}
                        </a>
                        {{if .HasWarnings}}
                            <span class="ml-2 text-amber-500">⚠️</span>
                        {{else}}
                            <span class="ml-2 text-green-500">✓</span>
                        {{end}}
                    </h2>
                    <svg class="chevron w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                    </svg>
                </div>
                <div class="collapsible-content">
                    <div class="space-y-4 mt-4">
                        {{$repoName := .Name}}
                        {{range .Workflows}}
                        <div class="border-t pt-4">
                            <h3 class="font-medium mb-2">
                                <a href="https://github.com/{{$repoName}}/blob/{{.Branch}}/{{.Name}}"
                                   target="_blank"
                                   class="text-gray-700 hover:text-gray-900">
                                    {{.Name}}
                                </a>
                            </h3>
                            <div class="overflow-x-auto">
                                <table class="min-w-full">
                                    <thead>
                                        <tr class="bg-gray-50">
                                            <th class="px-4 py-2 text-left text-sm font-medium text-gray-500">Action</th>
                                            <th class="px-4 py-2 text-right text-sm font-medium text-gray-500">Recommended Version</th>
                                            <th class="px-4 py-2 text-right text-sm font-medium text-gray-500 w-32">Version</th>
                                            <th class="px-4 py-2 text-right text-sm font-medium text-gray-500 w-24">Type</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-gray-200">
                                        {{range .Actions}}
                                        <tr class="hover:bg-gray-50
                                            {{if and (eq .Type "external") (not .IsHashedVersion)}}
                                                bg-orange-50
                                            {{end}}">
                                            <td class="px-4 py-2 text-sm">
                                                {{if eq .Type "external"}}
                                                    <a href="https://github.com/{{.Name}}"
                                                       target="_blank"
                                                       class="text-blue-600 hover:text-blue-800">
                                                        {{.Name}}
                                                    </a>
                                                {{else}}
                                                    {{.Name}}
                                                {{end}}
                                            </td>
                                            <td class="px-4 py-2 text-sm font-mono text-right">
                                                {{if and (eq .Type "external") (not .IsHashedVersion) .RecommendedHash}}
                                                    <span class="text-red-600">{{.RecommendedHash}}</span>
                                                {{end}}
                                                {{if and (eq .Type "external") (not .IsHashedVersion) .RecommendedHashReverseLookupVersion}}
                                                    <div class="text-xs text-gray-500">({{.RecommendedHashReverseLookupVersion}})</div>
                                                {{end}}
                                            </td>
                                            <td class="px-4 py-2 text-sm font-mono text-right">
                                                <span class="{{if .IsHashedVersion}}text-green-600{{end}}">
                                                    {{.Version}}
                                                </span>
                                                {{if and (eq .Type "external") (not .IsHashedVersion)}}
                                                    <span class="ml-2 text-amber-500 cursor-help" title="This version is not using a fixed git commit hash and could be vulnerable in the future">⚠️</span>
                                                {{end}}
                                                {{if and (eq .Type "external") .IsHashedVersion .VersionHashReverseLookupVersion}}
                                                    <div class="text-xs text-gray-500">({{.VersionHashReverseLookupVersion}})</div>
                                                {{end}}
                                            </td>
                                            <td class="px-4 py-2 text-sm text-right">
                                                <span class="px-2 py-1 rounded-full text-xs
                                                    {{if eq .Type "internal"}}
                                                        bg-gray-100 text-gray-800
                                                    {{else}}
                                                        bg-blue-100 text-blue-800
                                                    {{end}}">
                                                    {{.Type}}
                                                </span>
                                            </td>
                                        </tr>
                                        {{end}}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        {{end}}
                    </div>
                </div>
            </div>
            {{end}}
        </div>
    </div>

    <script>
        function toggleCollapse(element) {
            element.classList.toggle('expanded');
        }

        document.getElementById('expandAllBtn').addEventListener('click', function() {
            const sections = document.querySelectorAll('.collapsible-section');
            const isExpanding = this.textContent.trim() === 'Expand All';

            sections.forEach(section => {
                if (isExpanding) {
                    section.classList.add('expanded');
                } else {
                    section.classList.remove('expanded');
                }
            });

            this.textContent = isExpanding ? 'Collapse All' : 'Expand All';
        });
    </script>
</body>
</html>
`
