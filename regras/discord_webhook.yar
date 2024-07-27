rule discord_webhook {
	strings:
		$discord_webhook = /http?:\/\/(ptb\.|canary\.)?discord(app)?\.com\/api(\/v\d{1,2})?\/webhooks\/(\d{17,21})\/([\w-]{68})/i ascii wide nocase
	condition:
		any of them
}