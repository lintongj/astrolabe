package main

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"

	// restClient is the underlying REST/Swagger client
	restClient "github.com/vmware-tanzu/astrolabe/gen/client"
	"github.com/vmware-tanzu/astrolabe/pkg/astrolabe"

	// astrolabeClient is the Astrolabe API on top of the REST client
	"io"
	"log"
	"os"

	astrolabeClient "github.com/vmware-tanzu/astrolabe/pkg/client"
	"github.com/vmware-tanzu/astrolabe/pkg/server"
)

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "host",
				Usage: "Astrolabe server",
			},
			&cli.BoolFlag{
				Name:     "insecure",
				Usage:    "Only use HTTP",
				Required: false,
				Hidden:   false,
				Value:    false,
			},
			&cli.StringFlag{
				Name:  "confDir",
				Usage: "Configuration directory",
			},
		},
		Commands: []*cli.Command{
			{
				Name:   "types",
				Usage:  "shows Protected Entity Types",
				Action: types,
			},
			{
				Name:   "ls",
				Usage:  "lists entities for a type",
				Action: ls,
			},
			{
				Name:      "show",
				Usage:     "shows info for a protected entity",
				ArgsUsage: "<protected entity id>",
				Action:    show,
			},
			{
				Name:      "lssn",
				Usage:     "lists snapshots for a Protected Entity",
				Action:    lssn,
				ArgsUsage: "<protected entity id>",
			},
			{
				Name:      "snap",
				Usage:     "snapshots a Protected Entity",
				Action:    snap,
				ArgsUsage: "<protected entity id>",
			},
			{
				Name:      "rmsn",
				Usage:     "removes a Protected Entity snapshot",
				Action:    rmsn,
				ArgsUsage: "<protected entity snapshot id>",
			},
			{
				Name:      "cp",
				Usage:     "copies a Protected Entity snapshot to a zip file or copies a zip file to a Protected Entity",
				Action:    cp,
				ArgsUsage: "<src> <dest>",
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func setupProtectedEntityManager(c *cli.Context) (pem astrolabe.ProtectedEntityManager, err error) {
	confDirStr := c.String("confDir")
	if confDirStr != "" {
		pem = server.NewProtectedEntityManager(confDirStr)
		return
	}
	host := c.String("host")
	if host != "" {
		insecure := c.Bool("insecure")
		transport := restClient.DefaultTransportConfig()
		transport.Host = host
		if insecure {
			transport.Schemes = []string{"http"}
		}

		restClient := restClient.NewHTTPClientWithConfig(nil, transport)
		pem, err = astrolabeClient.NewClientProtectedEntityManager(restClient)
		if err != nil {
			err = errors.Wrap(err, "Failed to create new ClientProtectedEntityManager")
			return
		}
		return
	}
	err = errors.New("No configuration parameters supplied")
	return
}

func types(c *cli.Context) error {
	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}
	for _, curPETM := range pem.ListEntityTypeManagers() {
		fmt.Println(curPETM.GetTypeName())
	}
	return nil
}

func ls(c *cli.Context) error {
	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}
	peType := c.Args().First()
	petm := pem.GetProtectedEntityTypeManager(peType)
	if petm == nil {
		log.Fatalf("Could not find type named %s", peType)
	}
	peIDs, err := petm.GetProtectedEntities(context.Background())
	if err != nil {
		log.Fatalf("Could not retrieve protected entities for type %s err:%b", peType, err)
	}

	for _, curPEID := range peIDs {
		fmt.Println(curPEID.String())
	}
	return nil
}

func lssn(c *cli.Context) error {
	peIDStr := c.Args().First()
	peID, err := astrolabe.NewProtectedEntityIDFromString(peIDStr)
	if err != nil {
		log.Fatalf("Could not parse protected entity ID %s, err: %v", peIDStr, err)
	}

	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}

	pe, err := pem.GetProtectedEntity(context.Background(), peID)
	if err != nil {
		log.Fatalf("Could not retrieve protected entity ID %s, err: %v", peIDStr, err)
	}

	snaps, err := pe.ListSnapshots(context.Background())
	if err != nil {
		log.Fatalf("Could not get snapshots for protected entity ID %s, err: %v", peIDStr, err)
	}

	for _, curSnapshotID := range snaps {
		curPESnapshotID := peID.IDWithSnapshot(curSnapshotID)
		fmt.Println(curPESnapshotID.String())
	}
	return nil
}

func show(c *cli.Context) error {
	peIDStr := c.Args().First()
	peID, err := astrolabe.NewProtectedEntityIDFromString(peIDStr)
	if err != nil {
		log.Fatalf("Could not parse protected entity ID %s, err: %v", peIDStr, err)
	}

	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}

	pe, err := pem.GetProtectedEntity(context.Background(), peID)
	if err != nil {
		log.Fatalf("Could not retrieve protected entity ID %s, err: %v", peIDStr, err)
	}

	info, err := pe.GetInfo(context.Background())
	if err != nil {
		log.Fatalf("Could not retrieve info for %s, err: %v", peIDStr, err)
	}
	fmt.Printf("%v\n", info)
	return nil
}

func snap(c *cli.Context) error {
	peIDStr := c.Args().First()
	peID, err := astrolabe.NewProtectedEntityIDFromString(peIDStr)
	if err != nil {
		log.Fatalf("Could not parse protected entity ID %s, err: %v", peIDStr, err)
	}

	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}

	pe, err := pem.GetProtectedEntity(context.Background(), peID)
	if err != nil {
		log.Fatalf("Could not retrieve protected entity ID %s, err: %v", peIDStr, err)
	}
	snap, err := pe.Snapshot(context.Background(), make(map[string]map[string]interface{}))
	if err != nil {
		log.Fatalf("Could not snapshot protected entity ID %s, err: %v", peIDStr, err)
	}
	fmt.Println(snap.String())
	return nil
}

func rmsn(c *cli.Context) error {
	peIDStr := c.Args().First()
	peID, err := astrolabe.NewProtectedEntityIDFromString(peIDStr)
	if err != nil {
		log.Fatalf("Could not parse protected entity ID %s, err: %v", peIDStr, err)
	}
	if !peID.HasSnapshot() {
		log.Fatalf("Protected entity ID %s does not have a snapshot ID", peIDStr)
	}

	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err =%v", err)
	}

	pe, err := pem.GetProtectedEntity(context.Background(), peID)
	if err != nil {
		log.Fatalf("Could not retrieve protected entity ID %s, err: %v", peIDStr, err)
	}
	success, err := pe.DeleteSnapshot(context.Background(), peID.GetSnapshotID(), make(map[string]map[string]interface{}))
	if err != nil {
		log.Fatalf("Could not remove snapshot ID %s, err: %v", peIDStr, err)
	}
	if success {
		log.Printf("Removed snapshot %s\n", peIDStr)
	}
	return nil
}

func cp(c *cli.Context) error {
	if c.NArg() != 2 {
		log.Fatalf("Expected two arguments for cp, got %d", c.NArg())
	}
	srcStr := c.Args().First()
	destStr := c.Args().Get(1)
	ctx := context.Background()
	var err error
	var srcPE, destPE astrolabe.ProtectedEntity
	var srcPEID, destPEID astrolabe.ProtectedEntityID
	var srcFile, destFile string
	srcPEID, err = astrolabe.NewProtectedEntityIDFromString(srcStr)
	if err != nil {
		srcFile = srcStr
	}
	destPEID, err = astrolabe.NewProtectedEntityIDFromString(destStr)
	if err != nil {
		destFile = destStr
	}
	pem, err := setupProtectedEntityManager(c)
	if err != nil {
		log.Fatalf("Could not setup protected entity manager, err = %v", err)
	}

	var reader io.ReadCloser
	var writer io.WriteCloser
	fmt.Printf("cp from ")
	if srcFile != "" {
		fmt.Printf("file %s", srcFile)
	} else {
		fmt.Printf("pe %s", srcPEID.String())
		srcPE, err = pem.GetProtectedEntity(ctx, srcPEID)
		if err != nil {
			log.Fatalf("Could not retrieve protected entity ID %s, err: %v", srcPEID.String(), err)
		}
	}
	fmt.Printf(" to ")
	if destFile != "" {
		fmt.Printf("file %s", destFile)
	} else {
		fmt.Printf("pe %s", destPEID.String())
		destPE, err = pem.GetProtectedEntity(ctx, destPEID)
		if err != nil {
			log.Fatalf("Could not retrieve protected entity ID %s, err: %v", destPEID.String(), err)
		}
	}
	fmt.Printf("\n")

	var bytesCopied int64
	if srcPE != nil && destFile != "" {
		// copy a src pe snapshot to a dest file
		var zipFileWriter io.WriteCloser
		zipFileWriter, err = os.Create(destFile)
		if err != nil {
			log.Fatalf("Could not create file %s, err: %v", destFile, err)
		}
		defer func() {
			if err := zipFileWriter.Close(); err != nil {
				log.Fatalf("Could not close file %s, err: %v", destFile, err)
			}
		}()

		bytesCopied, err = astrolabe.ZipProtectedEntityToFile(ctx, srcPE, zipFileWriter)
	} else if srcFile != "" && destPE != nil {
		// copy a src file to an existing dest pe. BTW, the dest pe should be unconsumed.
		file, err := os.Open(srcFile)
		if err != nil {
			log.Fatalf("Could not open srcFile %s, err = %v", srcFile, err)
		}
		defer file.Close()

		fileInfo, err := file.Stat()
		if err != nil {
			log.Fatalf("Got err %v getting stat for source file %v", err, srcFile)
		}

		err = astrolabe.UnzipFileToProtectedEntity(ctx, file, fileInfo.Size(), destPE)
		bytesCopied = fileInfo.Size()
	} else {
		reader, err = os.Open(srcFile)
		if err != nil {
			log.Fatalf("Could not open srcFile %s, err = %v", srcFile, err)
		}
		defer reader.Close()

		bytesCopied, err = io.Copy(writer, reader)
	}

	if err != nil {
		log.Fatalf("Error copying %v", err)
	}

	fmt.Printf("Copied %d bytes\n", bytesCopied)

	return nil
}
