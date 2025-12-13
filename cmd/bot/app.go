package main

import (
	"domain-monitor/internal/api"
	"domain-monitor/internal/config"
	"domain-monitor/internal/googlesafebrowsing"
	"domain-monitor/internal/keitaro"
	"domain-monitor/internal/models"
	"domain-monitor/internal/monitor"
	"domain-monitor/internal/storage"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

type App struct {
	Bot     *tgbotapi.BotAPI
	Config  *config.Config
	Keitaro *keitaro.Client
	GSB     *googlesafebrowsing.Client
	Storage *storage.Storage
	Monitor *monitor.SmartMonitor
}

func NewApp(cfg *config.Config) (*App, error) {
	bot, err := tgbotapi.NewBotAPI(cfg.TelegramBotToken)
	if err != nil {
		return nil, err
	}

	bot.Debug = true

	storage, err := storage.NewStorage("./monitor.db")
	if err != nil {
		return nil, err
	}

	smartMonitor := monitor.NewSmartMonitor(storage, cfg.VirusTotalAPIKey)

	return &App{
		Bot:     bot,
		Config:  cfg,
		Keitaro: keitaro.New(cfg.KeytaroAPIKey, cfg.KeytaroURL),
		GSB:     googlesafebrowsing.New(cfg.GoogleSafeBrowsingAPIKey),
		Storage: storage,
		Monitor: smartMonitor,
	}, nil
}

func (app *App) CheckDomain(domain string) (*models.VTDetailReport, error) {
	return api.CheckDomain(domain, app.Config.VirusTotalAPIKey)
}

func (app *App) CheckDomainRaw(domain string) (*models.RawReport, error) {
	return api.CheckDomainRaw(domain, app.Config.VirusTotalAPIKey)
}
