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
	Name      string
	Workflows []WorkflowSummary
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

	var deps []ActionDependency
	if err := json.Unmarshal(data, &deps); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate HTML report
	outputFile := strings.TrimSuffix(filepath.Base(inputFile), ".json") + ".html"
	outputPath := filepath.Join(OutputDir, outputFile)

	if err := generateHTMLReport(inputFile, outputPath, deps, generatedTime); err != nil {
		return err
	}

	fmt.Printf("Report generated at %s\n", outputPath)
	return nil
}

// Create a shared function for HTML report generation
func generateHTMLReport(jsonFilePath, outputPath string, deps []ActionDependency, generatedTime string) error {
	// Calculate statistics
	var externalWithHash, externalWithoutHash int
	for _, dep := range deps {
		for _, action := range dep.Actions {
			if action.Type == "external" {
				if action.IsHashedVersion {
					externalWithHash++
				} else {
					externalWithoutHash++
				}
			}
		}
	}

	// Organize data by repository
	repoMap := make(map[string]*RepoSummary)
	for _, dep := range deps {
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

	// Convert map to sorted slice
	repos := make([]*RepoSummary, 0, len(repoMap))
	for _, repo := range repoMap {
		// Sort workflows by name
		sort.Slice(repo.Workflows, func(i, j int) bool {
			return repo.Workflows[i].Name < repo.Workflows[j].Name
		})
		repos = append(repos, repo)
	}
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].Name < repos[j].Name
	})

	// Read the JSON data for embedding in the report
	jsonData, err := os.ReadFile(jsonFilePath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %w", err)
	}

	// Generate HTML report
	tmpl := template.Must(template.New("report").Parse(reportTemplate))

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	embedData := []byte(fmt.Sprintf(`
	const reportData = %s;
	`, string(jsonData)))

	if err := tmpl.Execute(f, struct {
		Repos               []*RepoSummary
		JSONData            template.JS
		InputFile           string
		ExternalWithHash    int
		ExternalWithoutHash int
		GeneratedTime       string
	}{
		Repos:               repos,
		JSONData:            template.JS(embedData),
		InputFile:           filepath.Base(jsonFilePath),
		ExternalWithHash:    externalWithHash,
		ExternalWithoutHash: externalWithoutHash,
		GeneratedTime:       generatedTime,
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
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold">GitHub Actions Report</h1>
            <div class="text-right">
                <div class="text-gray-600">Source: {{.InputFile}}</div>
                <div class="text-gray-600">Generated on: {{.GeneratedTime}}</div>
            </div>
        </div>

        <!-- Summary Section -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h2 class="text-xl font-semibold mb-4">Summary</h2>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="bg-green-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-green-700">{{.ExternalWithHash}}</div>
                    <div class="text-sm text-green-600">External dependencies with hashed version</div>
                </div>
                <div class="bg-red-50 p-4 rounded-lg">
                    <div class="text-3xl font-bold text-red-700">{{.ExternalWithoutHash}}</div>
                    <div class="text-sm text-red-600">External dependencies without hashed version</div>
                </div>
            </div>
        </div>

        <div class="space-y-6">
            {{range .Repos}}
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold mb-4">
                    <a href="https://github.com/{{.Name}}" target="_blank" class="text-blue-600 hover:text-blue-800">
                        {{.Name}}
                    </a>
                </h2>
                <div class="space-y-4">
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
                                        <th class="px-4 py-2 text-right text-sm font-medium text-gray-500">Recommended Hash</th>
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
                                        </td>
                                        <td class="px-4 py-2 text-sm text-right">
                                            <span class="{{if .IsHashedVersion}}text-green-600{{end}}">
                                                {{.Version}}
                                            </span>
                                            {{if and (eq .Type "external") (not .IsHashedVersion)}}
                                                <span class="ml-2 text-amber-500 cursor-help" title="This version is not using a fixed git commit hash and could be vulnerable in the future">⚠️</span>
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
            {{end}}
        </div>
    </div>
</body>
</html>
`
