package main

import (
	"log"
	"os"
	"io"
	"fmt"
	// "os"
	"os/exec"
	// "strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/joho/godotenv"
	"bytes"

)

func main() {

	logFile, err := os.OpenFile("log/bot.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	err = godotenv.Load()
	if err != nil {
		log.Fatal("Please add your api token in .env file with BOT_API_KEY=your_token")
	}

	botToken := os.Getenv("BOT_API_KEY")

bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Fatal(err)
	}

	// bot.Debug = true

	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		fmt.Print("$")
		if update.Message != nil { // If we got a message
			// log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)

		
			// bot.Send(msg)
			fmt.Println(update.Message.Text)
			logger.Println(update.Message.Text)

			cmd := exec.Command("sh", "-c", fmt.Sprintf("%s",update.Message.Text))
			var out bytes.Buffer
		  cmd.Stdout = &out

		  cmd.Stderr = os.Stderr 
		  err = cmd.Run()
		  if err != nil {
			   fmt.Println("invalid Command");
		}
			msg := tgbotapi.NewMessage(update.Message.Chat.ID, out.String())
			msg.ReplyToMessageID = update.Message.MessageID

				  bot.Send(msg)

		}
	}
}
