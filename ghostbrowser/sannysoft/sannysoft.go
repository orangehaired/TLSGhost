package sannysoft

import (
	"fmt"
	"github.com/orangehaired/TLSGhost/ghostbrowser"
	"log"
	"os"
	"time"

	"github.com/go-rod/rod"
)

func Run() error {
	browser := rod.New().MustConnect()
	defer browser.MustClose()

	page, _ := ghostbrowser.CreateContext(browser)

	err := page.Navigate("https://bot.sannysoft.com")
	if err != nil {
		return err
	}

	time.Sleep(3 * time.Second)

	ss, err := page.Screenshot(true, nil)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("sannysoft_bypass_result-%d.png", time.Now().Unix())

	err = os.WriteFile(filename, ss, 0644)
	if err != nil {
		return err
	}
	log.Printf("✅ Screenshot taken: %s\n", filename)
	return nil
}
