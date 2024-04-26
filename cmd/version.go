package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func version(gitTag, buildTime *string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the build version and build time",
		Run: func(cmd *cobra.Command, args []string) {
			if len(*gitTag) == 0 {
				fmt.Fprintln(os.Stderr, "Unable to determine version because the build process did not properly configure it.")
			} else {
				fmt.Printf("Version:\t%s\n", *gitTag)
			}

			if len(*buildTime) == 0 {
				fmt.Fprintln(os.Stderr, "Unable to determine build timestamp because the build process did not properly configure it.")
			} else {
				fmt.Printf("build.Time:\t%s\n", *buildTime)
			}
		},
	}
}
