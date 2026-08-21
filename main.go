package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yeka/zip"
)

func loadPasswords(ctx context.Context, gzPath string) (<-chan string, <-chan error) {
	out := make(chan string, 4096)
	errc := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errc)

		f, err := os.Open(gzPath)
		if err != nil {
			errc <- err
			return
		}
		defer f.Close()

		gz, err := gzip.NewReader(f)
		if err != nil {
			errc <- err
			return
		}
		defer gz.Close()

		scanner := bufio.NewScanner(gz)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			password := strings.TrimSpace(scanner.Text())
			if password == "" {
				continue
			}
			select {
			case out <- password:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errc <- err
		}
	}()

	return out, errc
}

func readZipIntoMemory(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func tryPassword(data []byte, password string) (bool, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, err
	}

	for _, f := range r.File {
		if !f.IsEncrypted() {
			continue
		}
		f.SetPassword(password)

		rc, err := f.Open()
		if err != nil {
			return false, nil
		}
		_, err = io.Copy(io.Discard, rc)
		rc.Close()
		if err != nil {
			return false, nil
		}
		return true, nil
	}

	return false, fmt.Errorf("no encrypted file found in archive")
}

// logger buffers writes and flushes on a timer, so many goroutines logging
// concurrently don't turn into a syscall-per-line bottleneck.
type logger struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newLogger() *logger {
	return &logger{w: bufio.NewWriterSize(os.Stdout, 64*1024)}
}

func (l *logger) Printf(format string, args ...any) {
	l.mu.Lock()
	fmt.Fprintf(l.w, format, args...)
	l.mu.Unlock()
}

func (l *logger) Flush() {
	l.mu.Lock()
	l.w.Flush()
	l.mu.Unlock()
}

func main() {
	const zipPath = "cctest.zip"
	const wordlistPath = "crackstation-human-only.txt.gz"

	f, err := os.Open(zipPath)
	if err != nil {
		panic(err)
	}
	header := make([]byte, 64)
	if _, err := io.ReadFull(f, header); err != nil {
		f.Close()
		panic(err)
	}
	f.Close()

	isZip := header[0] == 0x50 && header[1] == 0x4B &&
		((header[2] == 0x03 && header[3] == 0x04) ||
			(header[2] == 0x05 && header[3] == 0x06) ||
			(header[2] == 0x07 && header[3] == 0x08))
	fmt.Printf("header: %x\n", header)
	fmt.Println("isZip:", isZip)
	if !isZip {
		fmt.Println("not a zip file, aborting")
		return
	}

	fmt.Println("reading zip into memory...")
	data, err := readZipIntoMemory(zipPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("loaded %d bytes\n", len(data))

	fmt.Println("running sanity check (this decompresses the target file once)...")
	sanityStart := time.Now()
	if _, err := tryPassword(data, "__sanity_check__"); err != nil {
		fmt.Println("Error inspecting archive:", err)
		return
	}
	fmt.Printf("sanity check took %s -- this tells you the per-attempt cost\n", time.Since(sanityStart))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	passwords, errc := loadPasswords(ctx, wordlistPath)

	log := newLogger()
	numWorkers := runtime.NumCPU()
	fmt.Printf("starting %d workers\n", numWorkers)

	var (
		wg       sync.WaitGroup
		found    atomic.Bool
		foundPw  atomic.Value
		attempts atomic.Int64
	)

	// Periodic progress + log flush, independent of worker count.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		last := int64(0)
		for {
			select {
			case <-ticker.C:
				log.Flush()
				n := attempts.Load()
				fmt.Printf("[stats] %d attempts (%d/sec)\n", n, n-last)
				last = n
			case <-stop:
				log.Flush()
				return
			}
		}
	}()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for pw := range passwords {
				if found.Load() {
					return
				}
				attempts.Add(1)
				log.Printf("[w%d] trying: %s\n", id, pw)

				ok, err := tryPassword(data, pw)
				if err != nil {
					continue
				}
				if ok {
					if found.CompareAndSwap(false, true) {
						foundPw.Store(pw)
						cancel()
					}
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(stop)

	if err, ok := <-errc; ok && err != nil {
		fmt.Println("Error reading password list:", err)
	}

	if found.Load() {
		fmt.Printf("\nPassword found: %s (after ~%d attempts)\n", foundPw.Load(), attempts.Load())
	} else {
		fmt.Printf("\nPassword not found (%d attempts)\n", attempts.Load())
	}
}
