package tui

import (
	"strings"
	"sync"
)

// -----------------------------------------------------------------------------
// Lightweight i18n. All user-visible UI strings go through tr("key") which
// looks up the active language. Default is English; user can switch via
// ".language <code>" at runtime. Persisted in Settings.Language.
//
// Supported codes:
//   en — English (default)
//   ru — Русский
//   de — Deutsch
//   fr — Français
//   zh — 中文
//   ja — 日本語
//
// This is intentionally shallow — only strings that appear in panels,
// banners, and the dropdown hints are translated. Log messages from
// pkg/f2f stay in Russian for now (changing those would touch the
// protocol-facing code).
// -----------------------------------------------------------------------------

var (
	i18nMu   sync.RWMutex
	i18nLang = "en"
)

// SetLanguage swaps the active UI language. Unknown codes fall back to "en".
func SetLanguage(code string) {
	code = strings.ToLower(strings.TrimSpace(code))
	if _, ok := i18nStrings[code]; !ok {
		code = "en"
	}
	i18nMu.Lock()
	i18nLang = code
	i18nMu.Unlock()
}

// CurrentLanguage returns the active language code.
func CurrentLanguage() string {
	i18nMu.RLock()
	defer i18nMu.RUnlock()
	return i18nLang
}

// tr returns the translated string for key in the active language,
// falling back to English, falling back to the key itself.
func tr(key string) string {
	i18nMu.RLock()
	lang := i18nLang
	i18nMu.RUnlock()

	if m, ok := i18nStrings[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := i18nStrings["en"]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}

// i18nStrings maps lang → key → translation. Kept as a Go map (not JSON
// files) so typos are caught at compile time and the binary has no
// external runtime deps.
var i18nStrings = map[string]map[string]string{
	"en": {
		"welcome.title":      "WELCOME",
		"welcome.tagline":    "ASKI CHAT — decentralised P2P messenger",
		"welcome.sec":        "Double Ratchet + XChaCha20-Poly1305 + Post-Compromise Security",
		"welcome.features":   "Voice calls (Opus 48k), ASCII video, file transfer",
		"welcome.start":      "Getting started:",
		"welcome.bootstrap":  "connect to DHT",
		"welcome.addfriend":  "add a contact",
		"welcome.connect":    "open chat",
		"welcome.dothint":    "Press . in the input to see all commands. ? — full help.",

		"info.title":    "YOUR PROFILE",
		"info.nick":     "Nick:",
		"info.status":   "Status:",
		"info.peerid":   "PeerID:",
		"info.fp":       "FP:",
		"info.copyhint": ".copy — put the .addfriend string in the clipboard",
		"info.notlogged": "not logged in — .login <nick>",

		"contacts.title":  "CONTACTS",
		"contacts.empty":  "(empty) — .addfriend <nick> <peerID> <pubkey>",
		"status.inchat":   "in chat",
		"status.connected": "connected",
		"status.incoming": "incoming",
		"status.nochannel": "no channel",
		"status.online":   "online",
		"status.offline":  "offline",

		"footer.commands":  "commands",
		"footer.tab":       "autocomplete",
		"footer.help":      "help",
		"footer.quit":      "quit",

		"suggest.hint":  "  Up/Down | Tab autocomplete | Enter run | Esc cancel",

		"call.incoming":  "Incoming %s call from %s! (.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "Calling %s (%s). Waiting for .acceptcall. .hangup to cancel.",
		"call.active":    "[OK] %s call with %s started. .hangup to end.",
		"call.ended":     "Call with %s ended (%s) — %s",
		"call.voice":     "voice",
		"call.video":     "video",

		"lang.set": "[OK] language: %s",
		"lang.usage": "usage: .language [en|ru|de|fr|zh|ja]",
		"lang.current": "current language: %s",

		"settings.title":   "SETTINGS",
		"settings.input":   "Input device:",
		"settings.output":  "Output device:",
		"settings.autoplay": "Voice auto-play:",
		"settings.vsource":  "Video source:",
		"settings.camid":    "  camera id:",
		"settings.vfile":    "  file stub:",
		"settings.ffmpeg":   "ffmpeg:",
		"settings.cmdhint":  "Commands to change:",
		"settings.cmd.autoplay": "toggle voice auto-play",
		"settings.cmd.input":    "microphones (then .settings input <N>)",
		"settings.cmd.output":   "speakers (then .settings output <N>)",
		"settings.cmd.camera":   "video source (0=ASCII, 1..N=cameras)",
		"settings.cmd.file":     "set/clear video stub file",
		"settings.cmd.ffmpeg":   "download ffmpeg (once)",

		"panel.cameras.title":    "CAMERAS",
		"panel.cameras.ffmpeg_missing": "ffmpeg not installed — real cameras unavailable.",
		"panel.cameras.install_hint":  "Run .ffmpeg install to enable webcams.",
		"panel.cameras.none":     "No cameras found.",
		"panel.cameras.check":    "Check: Windows privacy / busy in another app / driver.",
		"panel.cameras.found":    "Found %d camera(s):",
		"panel.cameras.ascii_row": "0) ASCII avatar (no camera)",
		"panel.cameras.selected": "<- selected",
		"panel.cameras.pick":     "Pick: .settings camera <N>  (0 = ASCII avatar)",

		"panel.audio.pick_input":  "Pick: .settings input <N>  (0 = system default)",
		"panel.audio.pick_output": "Pick: .settings output <N>  (0 = system default)",
		"panel.audio.input_title":  "AUDIO INPUT",
		"panel.audio.output_title": "AUDIO OUTPUT",
		"panel.audio.none":         "(no devices found)",

		"fp.title":     "FINGERPRINT",
		"fp.notlogged": "not logged in",
		"fp.hint":      "Compare out-of-band (voice / other channel) with your contact.",

		"help.title":      "Help",
		"help.dot":        "start a command — list will appear below input",
		"help.updown":     "pick a command in the dropdown",
		"help.tab":        "autocomplete selected command",
		"help.enter":      "send message / run command",
		"help.pgudn":      "scroll chat",
		"help.esc":        "close autocomplete / help",
		"help.qmark":      "this help screen (input empty)",
		"help.ctrlc":      "quit",
		"help.cmds":       "Commands",
		"help.info_grp":   "profile + .addfriend copy",
		"help.list_grp":   "contacts + DHT search",
		"help.add_grp":    "add contact",
		"help.conn_grp":   "open chat",
		"help.ctrl_grp":   "chat control",
		"help.call_grp":   "voice / video call",
		"help.accept_grp": "accept / hang up a call",
		"help.video_grp":  "ASCII video during a call",
		"help.file_grp":   "send a file",
		"help.rec_grp":    "voice messages",
		"help.setup_grp":  "settings",
		"help.boot_grp":   "join DHT",
		"help.any_key":    "Press any key to close",

		"cmd.unknown":        "unknown command: %s (? for list)",
		"cmd.usage_call":     "usage: call <nick>",
		"cmd.usage_vidcall":  "usage: vidcall <nick>",
		"cmd.no_incoming":    "no incoming call",
		"cmd.no_active_call": "no active call",
		"cmd.need_active":    "call not started — see above",
		"cmd.hangup_err":     "hang up %s: %s",
		"cmd.no_video":       "video is not running",
		"cmd.open_chat_first": "open a chat first (sidebar → Enter) or /connect <nick>",
	},

	"ru": {
		"welcome.title":     "ДОБРО ПОЖАЛОВАТЬ",
		"welcome.tagline":   "ASKI CHAT — децентрализованный P2P-мессенджер",
		"welcome.sec":       "Double Ratchet + XChaCha20-Poly1305 + Post-Compromise Security",
		"welcome.features":  "Голосовые звонки (Opus 48k), ASCII-видео, передача файлов",
		"welcome.start":     "Начало работы:",
		"welcome.bootstrap": "подключиться к DHT",
		"welcome.addfriend": "добавить контакт",
		"welcome.connect":   "открыть чат",
		"welcome.dothint":   "Нажми . в поле ввода — появятся все команды. ? — развёрнутая справка.",

		"info.title":    "ВАШИ ДАННЫЕ",
		"info.nick":     "Ник:",
		"info.status":   "Статус:",
		"info.peerid":   "PeerID:",
		"info.fp":       "FP:",
		"info.copyhint": ".copy — скопировать строку .addfriend в буфер обмена",
		"info.notlogged": "не залогинен — .login <nick>",

		"contacts.title":  "КОНТАКТЫ",
		"contacts.empty":  "(пусто) — .addfriend <nick> <peerID> <pubkey>",
		"status.inchat":   "в чате",
		"status.connected": "соединён",
		"status.incoming": "вх.запрос",
		"status.nochannel": "нет канала",
		"status.online":   "онлайн",
		"status.offline":  "оффлайн",

		"footer.commands":  "команды",
		"footer.tab":       "автодополнить",
		"footer.help":      "help",
		"footer.quit":      "quit",

		"suggest.hint": "  Up/Down | Tab autocomplete | Enter запуск | Esc отмена",

		"call.incoming":  "Запрос на %s вызов от %s! (.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "Звоню %s (%s). Жду .acceptcall / .declinecall от собеседника. .hangup чтобы отменить.",
		"call.active":    "[OK] %s вызов с %s начат. .hangup чтобы завершить.",
		"call.ended":     "Вызов с %s завершён (%s) — %s",
		"call.voice":     "голосовой",
		"call.video":     "видео",

		"lang.set": "[OK] язык: %s",
		"lang.usage": "usage: .language [en|ru|de|fr|zh|ja]",
		"lang.current": "текущий язык: %s",

		"settings.title":    "НАСТРОЙКИ",
		"settings.input":    "Микрофон:",
		"settings.output":   "Колонки:",
		"settings.autoplay": "Автовоспроизведение:",
		"settings.vsource":  "Источник видео:",
		"settings.camid":    "  камера:",
		"settings.vfile":    "  файл:",
		"settings.ffmpeg":   "ffmpeg:",
		"settings.cmdhint":  "Команды для изменения:",
		"settings.cmd.autoplay": "переключить автовоспроизв. голосовых",
		"settings.cmd.input":    "микрофоны (затем .settings input <N>)",
		"settings.cmd.output":   "колонки (затем .settings output <N>)",
		"settings.cmd.camera":   "источник видео (0=ASCII, 1..N=камеры)",
		"settings.cmd.file":     "задать/сбросить файл-заглушку",
		"settings.cmd.ffmpeg":   "скачать ffmpeg (один раз)",

		"panel.cameras.title":    "КАМЕРЫ",
		"panel.cameras.ffmpeg_missing": "ffmpeg не установлен — реальные камеры недоступны.",
		"panel.cameras.install_hint":  "Запусти .ffmpeg install чтобы подключить веб-камеры.",
		"panel.cameras.none":     "Камер не найдено.",
		"panel.cameras.check":    "Проверь: приватность Windows / занятость другой программой / драйвер.",
		"panel.cameras.found":    "Найдено камер: %d",
		"panel.cameras.ascii_row": "0) ASCII-аватар (без камеры)",
		"panel.cameras.selected": "<- выбрано",
		"panel.cameras.pick":     "Выбрать: .settings camera <номер>  (0 = ASCII-аватар)",

		"panel.audio.pick_input":  "Выбрать: .settings input <N>  (0 = системный дефолт)",
		"panel.audio.pick_output": "Выбрать: .settings output <N>  (0 = системный дефолт)",
		"panel.audio.input_title":  "АУДИО ВХОД",
		"panel.audio.output_title": "АУДИО ВЫХОД",
		"panel.audio.none":         "(устройства не найдены)",

		"fp.title":     "FINGERPRINT",
		"fp.notlogged": "не залогинен",
		"fp.hint":      "Сверь с собеседником out-of-band (голосом / по другому каналу).",

		"help.title":      "Подсказка",
		"help.dot":        "начать команду — под инпутом появится список",
		"help.updown":     "выбор команды в подсказках",
		"help.tab":        "автодополнение выбранной команды",
		"help.enter":      "отправить сообщение / выполнить команду",
		"help.pgudn":      "пролистать чат",
		"help.esc":        "закрыть автодополнение / справку",
		"help.qmark":      "этот экран помощи (когда input пустой)",
		"help.ctrlc":      "выход",
		"help.cmds":       "Команды",
		"help.info_grp":   "свои данные + копия .addfriend",
		"help.list_grp":   "контакты + поиск в DHT",
		"help.add_grp":    "добавить контакт",
		"help.conn_grp":   "открыть чат",
		"help.ctrl_grp":   "управление чатом",
		"help.call_grp":   "голосовой / видео вызов",
		"help.accept_grp": "ответ / завершение вызова",
		"help.video_grp":  "ASCII-видео в вызове",
		"help.file_grp":   "отправить файл",
		"help.rec_grp":    "голосовые сообщения",
		"help.setup_grp":  "настройка",
		"help.boot_grp":   "подключиться к DHT",
		"help.any_key":    "Нажми любую клавишу чтобы закрыть",

		"cmd.unknown":        "неизвестная команда: %s (? — список)",
		"cmd.usage_call":     "usage: call <nick>",
		"cmd.usage_vidcall":  "usage: vidcall <nick>",
		"cmd.no_incoming":    "нет входящего вызова",
		"cmd.no_active_call": "нет активного вызова",
		"cmd.need_active":    "вызов не начат — см. выше",
		"cmd.hangup_err":     "завершить вызов с %s: %s",
		"cmd.no_video":       "видео не идёт",
		"cmd.open_chat_first": "сначала открой чат (сайдбар → Enter) или /connect <nick>",
	},

	"de": {
		"welcome.title":     "WILLKOMMEN",
		"welcome.tagline":   "ASKI CHAT — dezentraler P2P-Messenger",
		"welcome.sec":       "Double Ratchet + XChaCha20-Poly1305 + Post-Compromise Security",
		"welcome.features":  "Sprachanrufe (Opus 48k), ASCII-Video, Dateiübertragung",
		"welcome.start":     "Erste Schritte:",
		"welcome.bootstrap": "Mit DHT verbinden",
		"welcome.addfriend": "Kontakt hinzufügen",
		"welcome.connect":   "Chat öffnen",
		"welcome.dothint":   "Drücke . im Eingabefeld — alle Befehle erscheinen. ? — ausführliche Hilfe.",

		"info.title":    "DEIN PROFIL",
		"info.nick":     "Name:",
		"info.status":   "Status:",
		"info.peerid":   "PeerID:",
		"info.fp":       "FP:",
		"info.copyhint": ".copy — .addfriend-Zeile in Zwischenablage kopieren",
		"info.notlogged": "nicht angemeldet — .login <name>",

		"contacts.title":  "KONTAKTE",
		"contacts.empty":  "(leer) — .addfriend <nick> <peerID> <pubkey>",
		"status.inchat":   "im Chat",
		"status.connected": "verbunden",
		"status.incoming": "eingehend",
		"status.nochannel": "kein Kanal",
		"status.online":   "online",
		"status.offline":  "offline",

		"footer.commands":  "Befehle",
		"footer.tab":       "Autovervollst.",
		"footer.help":      "Hilfe",
		"footer.quit":      "beenden",

		"suggest.hint": "  Up/Down | Tab | Enter Start | Esc abbrechen",

		"call.incoming":  "Eingehender %s-Anruf von %s! (.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "Rufe %s an (%s). Warte auf .acceptcall. .hangup zum Abbrechen.",
		"call.active":    "[OK] %s-Anruf mit %s gestartet. .hangup zum Beenden.",
		"call.ended":     "Anruf mit %s beendet (%s) — %s",
		"call.voice":     "Sprach",
		"call.video":     "Video",

		"lang.set":     "[OK] Sprache: %s",
		"lang.usage":   "Verwendung: .language [en|ru|de|fr|zh|ja]",
		"lang.current": "aktuelle Sprache: %s",

		"settings.title":    "EINSTELLUNGEN",
		"settings.input":    "Mikrofon:",
		"settings.output":   "Lautsprecher:",
		"settings.autoplay": "Auto-Wiedergabe:",
		"settings.vsource":  "Videoquelle:",
		"settings.camid":    "  Kamera-ID:",
		"settings.vfile":    "  Datei:",
		"settings.ffmpeg":   "ffmpeg:",
		"settings.cmdhint":  "Zum Ändern:",
		"settings.cmd.autoplay": "Sprach-Autowiedergabe umschalten",
		"settings.cmd.input":    "Mikrofone (dann .settings input <N>)",
		"settings.cmd.output":   "Lautsprecher (dann .settings output <N>)",
		"settings.cmd.camera":   "Videoquelle (0=ASCII, 1..N=Kameras)",
		"settings.cmd.file":     "Platzhalter-Datei setzen/löschen",
		"settings.cmd.ffmpeg":   "ffmpeg herunterladen (einmalig)",

		"panel.cameras.title":         "KAMERAS",
		"panel.cameras.ffmpeg_missing": "ffmpeg nicht installiert — echte Kameras nicht verfügbar.",
		"panel.cameras.install_hint":  "Führe .ffmpeg install aus, um Webcams zu aktivieren.",
		"panel.cameras.none":          "Keine Kameras gefunden.",
		"panel.cameras.check":         "Prüfe: Windows-Datenschutz / andere App / Treiber.",
		"panel.cameras.found":         "Gefundene Kameras: %d",
		"panel.cameras.ascii_row":     "0) ASCII-Avatar (ohne Kamera)",
		"panel.cameras.selected":      "<- ausgewählt",
		"panel.cameras.pick":          "Auswählen: .settings camera <N>  (0 = ASCII)",

		"panel.audio.pick_input":   "Auswählen: .settings input <N>  (0 = Standard)",
		"panel.audio.pick_output":  "Auswählen: .settings output <N>  (0 = Standard)",
		"panel.audio.input_title":  "AUDIO EINGANG",
		"panel.audio.output_title": "AUDIO AUSGANG",
		"panel.audio.none":         "(keine Geräte gefunden)",

		"fp.title":     "FINGERPRINT",
		"fp.notlogged": "nicht angemeldet",
		"fp.hint":      "Mit Kontakt out-of-band vergleichen (Stimme / anderer Kanal).",

		"help.title":      "Hilfe",
		"help.dot":        "Befehl starten — Liste erscheint unter der Eingabe",
		"help.updown":     "Befehl wählen",
		"help.tab":        "gewählten Befehl einfügen",
		"help.enter":      "senden / ausführen",
		"help.pgudn":      "Chat scrollen",
		"help.esc":        "Autovervollständigung schließen",
		"help.qmark":      "dieser Hilfe-Bildschirm",
		"help.ctrlc":      "beenden",
		"help.cmds":       "Befehle",
		"help.info_grp":   "Profil + .addfriend kopieren",
		"help.list_grp":   "Kontakte + DHT-Suche",
		"help.add_grp":    "Kontakt hinzufügen",
		"help.conn_grp":   "Chat öffnen",
		"help.ctrl_grp":   "Chat steuern",
		"help.call_grp":   "Sprach-/Videoanruf",
		"help.accept_grp": "Anruf annehmen/beenden",
		"help.video_grp":  "ASCII-Video im Anruf",
		"help.file_grp":   "Datei senden",
		"help.rec_grp":    "Sprachnachrichten",
		"help.setup_grp":  "Einstellungen",
		"help.boot_grp":   "DHT beitreten",
		"help.any_key":    "Beliebige Taste zum Schließen",

		"cmd.unknown":         "unbekannter Befehl: %s (? für Liste)",
		"cmd.usage_call":      "Verwendung: call <name>",
		"cmd.usage_vidcall":   "Verwendung: vidcall <name>",
		"cmd.no_incoming":     "kein eingehender Anruf",
		"cmd.no_active_call":  "kein aktiver Anruf",
		"cmd.need_active":     "Anruf nicht gestartet",
		"cmd.hangup_err":      "Anruf mit %s beenden: %s",
		"cmd.no_video":        "Video läuft nicht",
		"cmd.open_chat_first": "öffne zuerst einen Chat oder /connect <name>",
	},

	"fr": {
		"welcome.title":     "BIENVENUE",
		"welcome.tagline":   "ASKI CHAT — messagerie P2P décentralisée",
		"welcome.sec":       "Double Ratchet + XChaCha20-Poly1305 + Post-Compromise Security",
		"welcome.features":  "Appels vocaux (Opus 48k), vidéo ASCII, transfert de fichiers",
		"welcome.start":     "Pour commencer :",
		"welcome.bootstrap": "se connecter au DHT",
		"welcome.addfriend": "ajouter un contact",
		"welcome.connect":   "ouvrir un chat",
		"welcome.dothint":   "Appuie . dans la saisie — toutes les commandes apparaissent. ? — aide complète.",

		"info.title":    "TON PROFIL",
		"info.nick":     "Nom :",
		"info.status":   "Statut :",
		"info.peerid":   "PeerID :",
		"info.fp":       "FP :",
		"info.copyhint": ".copy — copier la ligne .addfriend dans le presse-papiers",
		"info.notlogged": "non connecté — .login <nom>",

		"contacts.title":  "CONTACTS",
		"contacts.empty":  "(vide) — .addfriend <nom> <peerID> <pubkey>",
		"status.inchat":   "en chat",
		"status.connected": "connecté",
		"status.incoming": "entrant",
		"status.nochannel": "pas de canal",
		"status.online":   "en ligne",
		"status.offline":  "hors ligne",

		"footer.commands":  "commandes",
		"footer.tab":       "auto-complétion",
		"footer.help":      "aide",
		"footer.quit":      "quitter",

		"suggest.hint": "  Up/Down | Tab | Enter lancer | Esc annuler",

		"call.incoming":  "Appel %s entrant de %s ! (.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "Appel %s vers %s. Attente de .acceptcall. .hangup pour annuler.",
		"call.active":    "[OK] appel %s avec %s démarré. .hangup pour terminer.",
		"call.ended":     "Appel avec %s terminé (%s) — %s",
		"call.voice":     "vocal",
		"call.video":     "vidéo",

		"lang.set":     "[OK] langue : %s",
		"lang.usage":   "utilisation : .language [en|ru|de|fr|zh|ja]",
		"lang.current": "langue actuelle : %s",

		"settings.title":    "PARAMÈTRES",
		"settings.input":    "Microphone :",
		"settings.output":   "Haut-parleur :",
		"settings.autoplay": "Lecture auto :",
		"settings.vsource":  "Source vidéo :",
		"settings.camid":    "  caméra :",
		"settings.vfile":    "  fichier :",
		"settings.ffmpeg":   "ffmpeg :",
		"settings.cmdhint":  "Pour modifier :",
		"settings.cmd.autoplay": "activer/désactiver lecture auto",
		"settings.cmd.input":    "micros (puis .settings input <N>)",
		"settings.cmd.output":   "haut-parleurs (puis .settings output <N>)",
		"settings.cmd.camera":   "source vidéo (0=ASCII, 1..N=caméras)",
		"settings.cmd.file":     "fichier placeholder pour vidéo",
		"settings.cmd.ffmpeg":   "télécharger ffmpeg (une fois)",

		"panel.cameras.title":         "CAMÉRAS",
		"panel.cameras.ffmpeg_missing": "ffmpeg non installé — caméras indisponibles.",
		"panel.cameras.install_hint":  "Lance .ffmpeg install pour activer les webcams.",
		"panel.cameras.none":          "Aucune caméra trouvée.",
		"panel.cameras.check":         "Vérifie : confidentialité Windows / autre app / pilote.",
		"panel.cameras.found":         "Caméras trouvées : %d",
		"panel.cameras.ascii_row":     "0) Avatar ASCII (sans caméra)",
		"panel.cameras.selected":      "<- sélectionné",
		"panel.cameras.pick":          "Choisir : .settings camera <N>  (0 = ASCII)",

		"panel.audio.pick_input":   "Choisir : .settings input <N>  (0 = défaut)",
		"panel.audio.pick_output":  "Choisir : .settings output <N>  (0 = défaut)",
		"panel.audio.input_title":  "AUDIO ENTRÉE",
		"panel.audio.output_title": "AUDIO SORTIE",
		"panel.audio.none":         "(aucun appareil trouvé)",

		"fp.title":     "EMPREINTE",
		"fp.notlogged": "non connecté",
		"fp.hint":      "Comparer hors-bande (voix / autre canal) avec le contact.",

		"help.title":      "Aide",
		"help.dot":        "lance une commande — liste sous la saisie",
		"help.updown":     "choisir une commande",
		"help.tab":        "compléter la commande",
		"help.enter":      "envoyer / exécuter",
		"help.pgudn":      "défiler le chat",
		"help.esc":        "fermer l'autocomplétion",
		"help.qmark":      "cet écran d'aide",
		"help.ctrlc":      "quitter",
		"help.cmds":       "Commandes",
		"help.info_grp":   "profil + copie .addfriend",
		"help.list_grp":   "contacts + recherche DHT",
		"help.add_grp":    "ajouter un contact",
		"help.conn_grp":   "ouvrir chat",
		"help.ctrl_grp":   "gérer chat",
		"help.call_grp":   "appel vocal / vidéo",
		"help.accept_grp": "accepter / raccrocher",
		"help.video_grp":  "vidéo ASCII pendant l'appel",
		"help.file_grp":   "envoyer un fichier",
		"help.rec_grp":    "messages vocaux",
		"help.setup_grp":  "paramètres",
		"help.boot_grp":   "rejoindre DHT",
		"help.any_key":    "N'importe quelle touche pour fermer",

		"cmd.unknown":         "commande inconnue : %s (? pour la liste)",
		"cmd.usage_call":      "usage : call <nom>",
		"cmd.usage_vidcall":   "usage : vidcall <nom>",
		"cmd.no_incoming":     "aucun appel entrant",
		"cmd.no_active_call":  "aucun appel actif",
		"cmd.need_active":     "appel non démarré",
		"cmd.hangup_err":      "raccrocher avec %s : %s",
		"cmd.no_video":        "vidéo non active",
		"cmd.open_chat_first": "ouvre d'abord un chat ou /connect <nom>",
	},

	"zh": {
		"welcome.title":     "欢迎",
		"welcome.tagline":   "ASKI CHAT — 去中心化 P2P 通讯器",
		"welcome.sec":       "Double Ratchet + XChaCha20-Poly1305 + 后向安全",
		"welcome.features":  "语音通话（Opus 48k）、ASCII 视频、文件传输",
		"welcome.start":     "快速开始：",
		"welcome.bootstrap": "连接 DHT",
		"welcome.addfriend": "添加联系人",
		"welcome.connect":   "打开聊天",
		"welcome.dothint":   "在输入框按 . 查看所有命令。? — 详细帮助。",

		"info.title":    "你的资料",
		"info.nick":     "昵称：",
		"info.status":   "状态：",
		"info.peerid":   "PeerID：",
		"info.fp":       "指纹：",
		"info.copyhint": ".copy — 将 .addfriend 行复制到剪贴板",
		"info.notlogged": "未登录 — .login <昵称>",

		"contacts.title":  "联系人",
		"contacts.empty":  "(空) — .addfriend <昵称> <peerID> <pubkey>",
		"status.inchat":   "通话中",
		"status.connected": "已连接",
		"status.incoming": "呼入",
		"status.nochannel": "无通道",
		"status.online":   "在线",
		"status.offline":  "离线",

		"footer.commands":  "命令",
		"footer.tab":       "自动补全",
		"footer.help":      "帮助",
		"footer.quit":      "退出",

		"suggest.hint": "  上/下 | Tab 补全 | Enter 执行 | Esc 取消",

		"call.incoming":  "收到来自 %s 的%s呼叫！(.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "正在呼叫 %s (%s)。等待 .acceptcall。.hangup 取消。",
		"call.active":    "[OK] 与 %s 的%s通话已开始。.hangup 结束。",
		"call.ended":     "与 %s 的通话结束 (%s) — %s",
		"call.voice":     "语音",
		"call.video":     "视频",

		"lang.set":     "[OK] 语言：%s",
		"lang.usage":   "用法：.language [en|ru|de|fr|zh|ja]",
		"lang.current": "当前语言：%s",

		"settings.title":    "设置",
		"settings.input":    "麦克风：",
		"settings.output":   "扬声器：",
		"settings.autoplay": "自动播放：",
		"settings.vsource":  "视频源：",
		"settings.camid":    "  摄像头：",
		"settings.vfile":    "  文件：",
		"settings.ffmpeg":   "ffmpeg：",
		"settings.cmdhint":  "修改命令：",
		"settings.cmd.autoplay": "切换语音自动播放",
		"settings.cmd.input":    "麦克风 (然后 .settings input <N>)",
		"settings.cmd.output":   "扬声器 (然后 .settings output <N>)",
		"settings.cmd.camera":   "视频源 (0=ASCII, 1..N=摄像头)",
		"settings.cmd.file":     "设置/清除视频占位文件",
		"settings.cmd.ffmpeg":   "下载 ffmpeg (一次)",

		"panel.cameras.title":         "摄像头",
		"panel.cameras.ffmpeg_missing": "ffmpeg 未安装 — 无法使用真实摄像头。",
		"panel.cameras.install_hint":  "运行 .ffmpeg install 启用摄像头。",
		"panel.cameras.none":          "未找到摄像头。",
		"panel.cameras.check":         "检查：Windows 隐私 / 被其他程序占用 / 驱动。",
		"panel.cameras.found":         "找到摄像头：%d",
		"panel.cameras.ascii_row":     "0) ASCII 头像 (无摄像头)",
		"panel.cameras.selected":      "<- 已选",
		"panel.cameras.pick":          "选择：.settings camera <N>  (0 = ASCII)",

		"panel.audio.pick_input":   "选择：.settings input <N>  (0 = 默认)",
		"panel.audio.pick_output":  "选择：.settings output <N>  (0 = 默认)",
		"panel.audio.input_title":  "音频输入",
		"panel.audio.output_title": "音频输出",
		"panel.audio.none":         "(未找到设备)",

		"fp.title":     "指纹",
		"fp.notlogged": "未登录",
		"fp.hint":      "通过其他渠道（语音/其他通道）与联系人核对。",

		"help.title":      "帮助",
		"help.dot":        "开始命令 — 列表在输入框下显示",
		"help.updown":     "选择命令",
		"help.tab":        "自动补全",
		"help.enter":      "发送 / 执行",
		"help.pgudn":      "滚动聊天",
		"help.esc":        "关闭自动补全",
		"help.qmark":      "此帮助屏幕",
		"help.ctrlc":      "退出",
		"help.cmds":       "命令",
		"help.info_grp":   "资料 + 复制 .addfriend",
		"help.list_grp":   "联系人 + DHT 搜索",
		"help.add_grp":    "添加联系人",
		"help.conn_grp":   "打开聊天",
		"help.ctrl_grp":   "聊天控制",
		"help.call_grp":   "语音 / 视频通话",
		"help.accept_grp": "接听 / 挂断",
		"help.video_grp":  "通话中的 ASCII 视频",
		"help.file_grp":   "发送文件",
		"help.rec_grp":    "语音消息",
		"help.setup_grp":  "设置",
		"help.boot_grp":   "加入 DHT",
		"help.any_key":    "按任意键关闭",

		"cmd.unknown":         "未知命令：%s (? 显示列表)",
		"cmd.usage_call":      "用法：call <昵称>",
		"cmd.usage_vidcall":   "用法：vidcall <昵称>",
		"cmd.no_incoming":     "没有呼入",
		"cmd.no_active_call":  "没有活动通话",
		"cmd.need_active":     "通话未开始",
		"cmd.hangup_err":      "挂断 %s：%s",
		"cmd.no_video":        "视频未运行",
		"cmd.open_chat_first": "先打开聊天 或 /connect <昵称>",
	},

	"ja": {
		"welcome.title":     "ようこそ",
		"welcome.tagline":   "ASKI CHAT — 分散型 P2P メッセンジャー",
		"welcome.sec":       "Double Ratchet + XChaCha20-Poly1305 + 後方秘匿性",
		"welcome.features":  "音声通話（Opus 48k）、ASCII ビデオ、ファイル転送",
		"welcome.start":     "はじめに：",
		"welcome.bootstrap": "DHT に接続",
		"welcome.addfriend": "連絡先を追加",
		"welcome.connect":   "チャットを開く",
		"welcome.dothint":   "入力欄で . を押すと全コマンドが表示されます。? — 詳細ヘルプ。",

		"info.title":    "プロフィール",
		"info.nick":     "名前：",
		"info.status":   "状態：",
		"info.peerid":   "PeerID：",
		"info.fp":       "FP：",
		"info.copyhint": ".copy — .addfriend 行をクリップボードへ",
		"info.notlogged": "未ログイン — .login <名前>",

		"contacts.title":  "連絡先",
		"contacts.empty":  "(空) — .addfriend <名前> <peerID> <pubkey>",
		"status.inchat":   "通話中",
		"status.connected": "接続済み",
		"status.incoming": "着信",
		"status.nochannel": "チャネルなし",
		"status.online":   "オンライン",
		"status.offline":  "オフライン",

		"footer.commands":  "コマンド",
		"footer.tab":       "補完",
		"footer.help":      "ヘルプ",
		"footer.quit":      "終了",

		"suggest.hint": "  上下 | Tab 補完 | Enter 実行 | Esc 取消",

		"call.incoming":  "%s からの%s通話! (.acceptcall %s / .declinecall %s)",
		"call.outgoing":  "%s に発信 (%s)。.acceptcall を待機中。.hangup でキャンセル。",
		"call.active":    "[OK] %s との%s通話を開始。.hangup で終了。",
		"call.ended":     "%s との通話終了 (%s) — %s",
		"call.voice":     "音声",
		"call.video":     "ビデオ",

		"lang.set":     "[OK] 言語：%s",
		"lang.usage":   "使い方：.language [en|ru|de|fr|zh|ja]",
		"lang.current": "現在の言語：%s",

		"settings.title":    "設定",
		"settings.input":    "マイク：",
		"settings.output":   "スピーカー：",
		"settings.autoplay": "自動再生：",
		"settings.vsource":  "ビデオソース：",
		"settings.camid":    "  カメラ：",
		"settings.vfile":    "  ファイル：",
		"settings.ffmpeg":   "ffmpeg：",
		"settings.cmdhint":  "変更するには：",
		"settings.cmd.autoplay": "音声自動再生を切替",
		"settings.cmd.input":    "マイク (次に .settings input <N>)",
		"settings.cmd.output":   "スピーカー (次に .settings output <N>)",
		"settings.cmd.camera":   "ビデオソース (0=ASCII, 1..N=カメラ)",
		"settings.cmd.file":     "ビデオ代替ファイル設定/解除",
		"settings.cmd.ffmpeg":   "ffmpeg をダウンロード (一度)",

		"panel.cameras.title":         "カメラ",
		"panel.cameras.ffmpeg_missing": "ffmpeg 未インストール — 実カメラ利用不可。",
		"panel.cameras.install_hint":  ".ffmpeg install でカメラ有効化。",
		"panel.cameras.none":          "カメラが見つかりません。",
		"panel.cameras.check":         "確認：Windows プライバシー / 他アプリ / ドライバ。",
		"panel.cameras.found":         "カメラ数：%d",
		"panel.cameras.ascii_row":     "0) ASCII アバター (カメラなし)",
		"panel.cameras.selected":      "<- 選択済",
		"panel.cameras.pick":          "選択：.settings camera <N>  (0 = ASCII)",

		"panel.audio.pick_input":   "選択：.settings input <N>  (0 = 既定)",
		"panel.audio.pick_output":  "選択：.settings output <N>  (0 = 既定)",
		"panel.audio.input_title":  "オーディオ入力",
		"panel.audio.output_title": "オーディオ出力",
		"panel.audio.none":         "(デバイスなし)",

		"fp.title":     "フィンガープリント",
		"fp.notlogged": "未ログイン",
		"fp.hint":      "相手と別経路（音声など）で照合してください。",

		"help.title":      "ヘルプ",
		"help.dot":        "コマンド開始 — 入力欄下にリスト表示",
		"help.updown":     "コマンド選択",
		"help.tab":        "補完",
		"help.enter":      "送信 / 実行",
		"help.pgudn":      "チャットスクロール",
		"help.esc":        "補完を閉じる",
		"help.qmark":      "このヘルプ",
		"help.ctrlc":      "終了",
		"help.cmds":       "コマンド",
		"help.info_grp":   "プロフィール + .addfriend コピー",
		"help.list_grp":   "連絡先 + DHT 検索",
		"help.add_grp":    "連絡先追加",
		"help.conn_grp":   "チャット開く",
		"help.ctrl_grp":   "チャット操作",
		"help.call_grp":   "音声/ビデオ通話",
		"help.accept_grp": "応答/切断",
		"help.video_grp":  "通話中の ASCII ビデオ",
		"help.file_grp":   "ファイル送信",
		"help.rec_grp":    "ボイスメッセージ",
		"help.setup_grp":  "設定",
		"help.boot_grp":   "DHT 参加",
		"help.any_key":    "任意のキーで閉じる",

		"cmd.unknown":         "不明なコマンド：%s (? で一覧)",
		"cmd.usage_call":      "使い方：call <名前>",
		"cmd.usage_vidcall":   "使い方：vidcall <名前>",
		"cmd.no_incoming":     "着信なし",
		"cmd.no_active_call":  "アクティブな通話なし",
		"cmd.need_active":     "通話未開始",
		"cmd.hangup_err":      "%s との通話終了：%s",
		"cmd.no_video":        "ビデオ未起動",
		"cmd.open_chat_first": "先にチャットを開く / /connect <名前>",
	},
}

