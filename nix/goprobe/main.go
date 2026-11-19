// goprobe: a Go program for the suite and the flake's smoke check (static: CGO off), exercising
// what Go's runtime does differently from C programs: syscalls on small goroutine stacks, many
// threads (GOMAXPROCS of them, plus those blocked in syscalls), preemption of a busy goroutine by
// SIGURG, timers, and the netpoller (epoll) over loopback TCP, with an HTTP server and client in
// one process. Each check prints a line; the last is GOPROBE_OK.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func fail(format string, a ...any) {
	fmt.Printf("GOPROBE_FAIL "+format+"\n", a...)
	os.Exit(1)
}

// A function call the compiler keeps, with a stack check in its prologue (where cooperative
// preemption happens): not a leaf, since a small leaf function gets no check.
//
//go:noinline
func step(x int) int { return leaf(x) }

//go:noinline
func leaf(x int) int { return x + 1 }

// The checks beyond the default ones, by argument: preempt, asyncpreempt, exec.
var opt = map[string]bool{}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		os.Exit(7)
	}
	for _, a := range os.Args[1:] {
		opt[a] = true
	}
	// Goroutines and channels: a fan-out over more goroutines than threads.
	var wg sync.WaitGroup
	results := make(chan int, 1000)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results <- i
		}(i)
	}
	wg.Wait()
	close(results)
	sum := 0
	for r := range results {
		sum += r
	}
	if sum != 999*1000/2 {
		fail("goroutines: sum %d", sum)
	}
	fmt.Println("goroutines ok")

	// Timers: sleeps and a ticker, which must neither fire early nor stall.
	start := time.Now()
	t := time.NewTicker(5 * time.Millisecond)
	for i := 0; i < 4; i++ {
		<-t.C
	}
	t.Stop()
	time.Sleep(10 * time.Millisecond)
	if el := time.Since(start); el < 30*time.Millisecond || el > 3*time.Second {
		fail("timers: %v", el)
	}
	select {
	case <-time.After(20 * time.Millisecond):
	case <-time.After(5 * time.Second):
		fail("time.After")
	}
	fmt.Println("timers ok")

	// Preemption: with GOMAXPROCS(1), the main goroutine runs again only if a spinning one is
	// preempted, by sysmon (a thread of its own, asleep in its timed waits): cooperatively at the
	// spinner's next function call ("preempt"), or, in a loop with no calls, asynchronously by
	// SIGURG to its thread ("asyncpreempt", Go 1.14+). Neither in coroutine mode: its threads
	// are coroutines, and one in user code keeps the others (sysmon) from running.
	if opt["preempt"] || opt["asyncpreempt"] {
		prev := runtime.GOMAXPROCS(1)
		var stop atomic.Bool
		if opt["asyncpreempt"] {
			go func() {
				for !stop.Load() {
				}
			}()
		} else {
			go func() {
				x := 0
				for !stop.Load() {
					x = step(x)
				}
			}()
		}
		time.Sleep(time.Millisecond)
		runtime.Gosched()
		stop.Store(true)
		runtime.GOMAXPROCS(prev)
		fmt.Println("preemption ok")
	}

	// Parallel work on GOMAXPROCS threads, with garbage collection running alongside.
	var n atomic.Int64
	for i := 0; i < runtime.GOMAXPROCS(0)*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b := make([]byte, 64<<10)
				b[j] = byte(j)
				n.Add(int64(len(b)))
			}
		}()
	}
	wg.Wait()
	runtime.GC()
	fmt.Println("parallel ok")

	// The network: an HTTP server on loopback and concurrent clients, through the netpoller.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fail("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Millisecond)
		fmt.Fprintf(w, "hello %s", r.URL.Query().Get("n"))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	url := "http://" + ln.Addr().String() + "/hello?n="
	client := &http.Client{Timeout: 5 * time.Second}
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprint(url, i))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errs <- err
				return
			}
			if string(body) != fmt.Sprint("hello ", i) {
				errs <- fmt.Errorf("body %q", body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		fail("http: %v", err)
	}
	srv.Close()
	fmt.Println("http ok")

	// A child process, where the sandbox has processes (fork mode): fork and exec, as os/exec
	// does it (clone(CLONE_VFORK|CLONE_VM)), and its exit status.
	if opt["exec"] {
		p, err := os.StartProcess(os.Args[0], []string{os.Args[0], "child"}, &os.ProcAttr{Files: []*os.File{nil, os.Stdout, os.Stderr}})
		if err != nil {
			fail("exec: %v", err)
		}
		st, err := p.Wait()
		if err != nil || st.ExitCode() != 7 {
			fail("exec: %v %v", st, err)
		}
		fmt.Println("exec ok")
	}
	fmt.Println("GOPROBE_OK")
}
