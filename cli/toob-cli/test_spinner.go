package main

import (
	"time"
	"github.com/toob-boot/toob/internal/ui"
)

func main() {
	ui.Init()
	ui.Header("Testing Live Spinner")

	spinner := ui.NewSpinner("Compiling...")
	spinner.Start()

	// Simulate work and detail updates
	for i := 0; i <= 50; i++ {
		if i == 10 {
			spinner.UpdateDetail("❯ [10/50] Compiling src/main.c")
		}
		if i == 20 {
			spinner.UpdateDetail("❯ [20/50] Compiling src/utils.c")
		}
		if i == 30 {
			spinner.UpdateDetail("❯ [30/50] Linking firmware.elf")
		}
		
		// The easter egg is hardcoded in spinner.go to trigger after 5 seconds
		// and at modulo 10 seconds. This loop takes exactly 50 * 200ms = 10s.
		// Wait slightly longer on the last step to guarantee an easter egg is seen!
		if i == 45 {
			time.Sleep(3000 * time.Millisecond)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}

	spinner.Stop()
	ui.Success("Compilation complete!")
}
