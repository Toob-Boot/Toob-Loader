package main

import (
	"fmt"
	"time"

	"github.com/toob-boot/toob/internal/ui"
)

func main() {
	ui.Init()

	ui.Header("Interactive UI Test")

	// Test Select
	opt, err := ui.Select("Select Target Architecture", []string{
		"espressif/esp32c6",
		"espressif/esp32s3",
		"stmicro/stm32f4",
		"nordic/nrf52",
	})
	if err != nil {
		ui.Error("Aborted")
		return
	}
	ui.Info("You selected index %d", opt)

	// Test Confirm
	ok, err := ui.Confirm("Would you like to build the project now?", true)
	if err != nil {
		ui.Error("Aborted")
		return
	}

	if ok {
		// Test Spinner
		spinner := ui.NewSpinner("Building Firmware")
		spinner.Start()

		// Simulate compilation
		spinner.UpdateDetail("❯ [10/50] Compiling src/main.c")
		time.Sleep(1500 * time.Millisecond)

		spinner.UpdateDetail("❯ [20/50] Compiling src/utils.c")
		time.Sleep(1500 * time.Millisecond)

		spinner.UpdateDetail("❯ [30/50] Compiling hal/spi.c")
		// Wait longer to see the easter egg!
		time.Sleep(7500 * time.Millisecond) 

		spinner.UpdateDetail("❯ [50/50] Linking firmware.elf")
		time.Sleep(1000 * time.Millisecond)

		spinner.Stop()
		ui.Success("Firmware successfully built!")
	} else {
		ui.Muted("Build skipped.")
	}

	fmt.Println()
}
