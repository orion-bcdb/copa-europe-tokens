// Copyright IBM Corp. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/copa-europe-tokens/pkg/config"
	"github.com/copa-europe-tokens/pkg/server"
	"github.com/spf13/cobra"
)

var (
	configPath string
	// PathEnv is an environment variable that can hold the absolute path of the config file
	pathEnv = "COPA_TOKENS_CONFIG_PATH"
)

func main() {
	cmd := tokensCmd()

	// On failure Cobra prints the usage message and error string, so we only
	// need to exit with a non-0 status
	if cmd.Execute() != nil {
		os.Exit(1)
	}
}

func tokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "copaTokens",
		Short: "To start and interact with a COPA Europe tokens server.",
	}
	cmd.AddCommand(versionCmd())
	cmd.AddCommand(startCmd())
	return cmd
}

func versionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of the COPA Europe tokens server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("trailing arguments detected")
			}

			cmd.SilenceUsage = true
			cmd.Println("copaTokens v0.1")

			return nil
		},
	}

	return cmd
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Starts a COPA Europe tokens server",
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			switch {
			case configPath != "":
				path = configPath
			case os.Getenv(pathEnv) != "":
				path = os.Getenv(pathEnv)
			default:
				log.Fatalf("Neither --configpath nor %s path environment is set", pathEnv)
			}

			conf, err := config.Read(path)
			if err != nil {
				return err
			}

			cmd.SilenceUsage = true
			log.Println("Starting a copaTokens server")
			tokensServer, err := server.NewTokensServer(conf)
			if err != nil {
				return err
			}

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				if err := tokensServer.Start(); err != nil {
					wg.Done()
					log.Fatalf("%v", err)
				}
			}()
			wg.Wait()

			return nil
		},
	}

	cmd.PersistentFlags().StringVar(&configPath, "configpath", "", "set the absolute path of config directory")
	return cmd
}
