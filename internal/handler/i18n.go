package handler

import (
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// locale is the language a visitor-facing page renders in: Lang for the
// <html lang> attribute, T for the page's strings. Admin pages stay English.
type locale struct {
	Lang string
	T    map[string]template.HTML
}

// negotiateLocale picks the visitor's language from Accept-Language and
// marks the response as varying on it. Pages without a matching language
// fall back to English.
func negotiateLocale(w http.ResponseWriter, r *http.Request) locale {
	w.Header().Add("Vary", "Accept-Language")
	return pickLocale(r.Header.Get("Accept-Language"))
}

// pickLocale returns the supported language the header prefers most,
// matching on the primary subtag (de-AT → de). Traditional Chinese tags are
// skipped rather than served Simplified, so they fall through to the next
// preference or English.
func pickLocale(header string) locale {
	type pref struct {
		tag string
		q   float64
	}
	var prefs []pref
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		tag := strings.ToLower(strings.TrimSpace(fields[0]))
		if tag == "" || tag == "*" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if v, ok := strings.CutPrefix(f, "q="); ok {
				if n, err := strconv.ParseFloat(v, 64); err == nil {
					q = n
				}
			}
		}
		if q > 0 {
			prefs = append(prefs, pref{tag, q})
		}
	}
	sort.SliceStable(prefs, func(i, j int) bool { return prefs[i].q > prefs[j].q })

	for _, p := range prefs {
		primary, rest, _ := strings.Cut(p.tag, "-")
		if primary == "zh" && isTraditionalChinese(rest) {
			continue
		}
		if l, ok := locales[primary]; ok {
			return l
		}
	}
	return locales["en"]
}

func isTraditionalChinese(subtags string) bool {
	for _, s := range strings.Split(subtags, "-") {
		switch s {
		case "hant", "tw", "hk", "mo":
			return true
		}
	}
	return false
}

// messages holds every visitor-facing string. English is the reference set:
// TestLocalesComplete checks the others carry exactly its keys. Values are
// trusted HTML (some carry <br>, <strong> or a reload link).
var messages = map[string]map[string]template.HTML{
	"en": {
		"title_checking":   "Loupe — Checking your browser",
		"title_verify":     "Loupe — Verify",
		"title_blocked":    "Loupe — Access Denied",
		"title_unverified": "Loupe — Unable to Verify",

		"checking":               "Checking your browser",
		"checking_sub_challenge": "Loupe is verifying that you are human.<br>This usually only takes a moment.",
		"checking_sub_pulse":     "This will only take a moment.",
		"verify_heading":         "Please verify to continue.",
		"i_am_human":             "I am human",
		"progress_label":         "Verification progress",
		"verified":               "Verified!",
		"redirecting":            "Redirecting to the site ...",
		"failed":                 `Verification failed. <a href="">Refresh</a> to try again.`,

		"why": "Why am I seeing this?",

		"blocked_status":         "Sorry, you have been blocked.",
		"blocked_sub":            "Loupe could not verify the legitimacy of your traffic.<br>If you believe this is an error, please contact the website owner.",
		"blocked_why_intro":      "This website uses Loupe to protect itself from automated traffic. Your request was blocked because it came from a network, an IP address or software that looked automated, or because there were several failed verification attempts in a row.",
		"blocked_why_list_intro": "This can happen even if you did nothing wrong:",
		"blocked_why_shared":     "<strong>Shared networks.</strong> Someone else on your Wi-Fi, office, school or mobile network, or on your VPN or proxy, may have sent the traffic.",
		"blocked_why_vpn":        "<strong>VPNs, proxies and hosting providers.</strong> Addresses from these services are often misused, so they get less trust.",
		"blocked_why_ext":        "<strong>Browser extensions or scripts</strong> that send requests automatically or change how your browser identifies itself.",
		"blocked_why_todo":       "<strong>What you can do:</strong> Wait a while and try again, since some blocks lift on their own. You can also switch networks, for example by turning off your VPN or using mobile data instead of Wi-Fi. If the block continues, contact the website owner and include the <strong>Verdict ID</strong> shown below so they can look it up.",
		"title_ratelimited":      "Loupe — Too Many Requests",
		"ratelimited_status":     "You’re being rate limited.",
		"ratelimited_sub":        "Too many requests came from your connection in a short time.<br>Please wait a moment, then try again.",
		"ratelimited_wait":       "You can try again in {n} seconds.",
		"ratelimited_ready":      "You can try again now.",
		"ratelimited_retry":      "Try again",
		"ratelimited_why":        "The owner of this website limits how many requests each visitor can make in a short time, to keep the site fast and safe. This can happen to real people too, for example after reloading a page many times, or when many people share one network, office or VPN. The limit lifts on its own, so waiting is all you need to do.",

		"prism_status":         "Drag the piece into the matching gap to continue.",
		"prism_error":          "Incorrect placement — please try again.",
		"prism_loading":        "Loading puzzle…",
		"prism_loading_new":    "Loading new puzzle…",
		"continue":             "Continue →",
		"verifying":            "Verifying…",
		"prism_why_intro":      "Loupe noticed unusual traffic from your network and wants to make sure a person, not a program, is sending these requests. Solving the puzzle lets you continue to the site.",
		"prism_why_list_intro": "This can happen when:",
		"prism_why_lists":      "your IP address appears on public lists of addresses linked to abuse,",
		"prism_why_vpn":        "you're using a VPN, a proxy or a hosting provider's network,",
		"prism_why_network":    "other devices on your network have sent many automated requests, or",
		"prism_why_ext":        "a browser extension or script is sending requests for you.",
		"prism_why_after":      "Once you've passed, you won't be asked again for a while. If you keep seeing this page, a device or extension on your network may still be sending automated traffic.",

		"unverified_status": "Your browser couldn't be verified.",
		"unverified_before": "A setting or extension in your browser is blocking or changing what Loupe checks, such as disabled JavaScript or cookies, fingerprinting protection, or a user-agent switcher. Please turn it off for this site, then",
		"try_again":         "try again",
		"unverified_after":  ".",

		"verdict_id":     "Verdict ID:",
		"your_ip":        "Your IP:",
		"reveal":         "Click to reveal",
		"reveal_aria":    "Reveal your IP address",
		"secured_before": "Secured by Loupe from ",
		"secured_after":  ".",
	},

	"de": {
		"title_checking":   "Loupe — Browser wird überprüft",
		"title_verify":     "Loupe — Bestätigung",
		"title_blocked":    "Loupe — Zugriff verweigert",
		"title_unverified": "Loupe — Überprüfung nicht möglich",

		"checking":               "Ihr Browser wird überprüft",
		"checking_sub_challenge": "Loupe prüft, ob Sie ein Mensch sind.<br>Das dauert normalerweise nur einen Moment.",
		"checking_sub_pulse":     "Das dauert nur einen Moment.",
		"verify_heading":         "Bitte bestätigen Sie, um fortzufahren.",
		"i_am_human":             "Ich bin ein Mensch",
		"progress_label":         "Fortschritt der Überprüfung",
		"verified":               "Bestätigt!",
		"redirecting":            "Weiterleitung zur Website ...",
		"failed":                 `Überprüfung fehlgeschlagen. <a href="">Laden Sie die Seite neu</a>, um es erneut zu versuchen.`,

		"why": "Warum sehe ich diese Seite?",

		"blocked_status":         "Sie wurden leider blockiert.",
		"blocked_sub":            "Loupe konnte die Legitimität Ihres Datenverkehrs nicht bestätigen.<br>Wenn Sie glauben, dass es sich um einen Fehler handelt, wenden Sie sich bitte an den Betreiber der Website.",
		"blocked_why_intro":      "Diese Website schützt sich mit Loupe vor automatisiertem Datenverkehr. Ihre Anfrage wurde blockiert, weil sie aus einem Netzwerk, von einer IP-Adresse oder von einer Software kam, die automatisiert wirkte, oder weil es mehrere fehlgeschlagene Überprüfungsversuche hintereinander gab.",
		"blocked_why_list_intro": "Das kann auch passieren, wenn Sie nichts falsch gemacht haben:",
		"blocked_why_shared":     "<strong>Gemeinsam genutzte Netzwerke.</strong> Jemand anderes in Ihrem WLAN, Büro-, Schul- oder Mobilfunknetz oder in Ihrem VPN bzw. Proxy könnte den Datenverkehr verursacht haben.",
		"blocked_why_vpn":        "<strong>VPNs, Proxys und Hosting-Anbieter.</strong> Adressen dieser Dienste werden häufig missbraucht und gelten daher als weniger vertrauenswürdig.",
		"blocked_why_ext":        "<strong>Browsererweiterungen oder Skripte</strong>, die automatisch Anfragen senden oder verändern, wie sich Ihr Browser zu erkennen gibt.",
		"blocked_why_todo":       "<strong>Was Sie tun können:</strong> Warten Sie eine Weile und versuchen Sie es erneut, denn manche Sperren werden automatisch aufgehoben. Sie können auch das Netzwerk wechseln, zum Beispiel indem Sie Ihr VPN ausschalten oder mobile Daten statt WLAN verwenden. Wenn die Sperre bestehen bleibt, wenden Sie sich an den Betreiber der Website und geben Sie die unten angezeigte <strong>Verdict-ID</strong> an, damit der Vorfall nachvollzogen werden kann.",
		"title_ratelimited":      "Loupe — Zu viele Anfragen",
		"ratelimited_status":     "Ihre Anfragen werden gerade begrenzt.",
		"ratelimited_sub":        "Von Ihrer Verbindung kamen in kurzer Zeit zu viele Anfragen.<br>Bitte warten Sie einen Moment und versuchen Sie es dann erneut.",
		"ratelimited_wait":       "Sie können es in {n} Sekunden erneut versuchen.",
		"ratelimited_ready":      "Sie können es jetzt erneut versuchen.",
		"ratelimited_retry":      "Erneut versuchen",
		"ratelimited_why":        "Der Betreiber dieser Website begrenzt, wie viele Anfragen jeder Besucher in kurzer Zeit stellen kann, damit die Website schnell und sicher bleibt. Das kann auch echten Menschen passieren, zum Beispiel nach häufigem Neuladen einer Seite oder wenn sich viele Personen ein Netzwerk, ein Büro oder ein VPN teilen. Die Begrenzung endet von selbst, Sie müssen nur kurz warten.",

		"prism_status":         "Ziehen Sie das Teil in die passende Lücke, um fortzufahren.",
		"prism_error":          "Falsch platziert – bitte versuchen Sie es erneut.",
		"prism_loading":        "Puzzle wird geladen…",
		"prism_loading_new":    "Neues Puzzle wird geladen…",
		"continue":             "Weiter →",
		"verifying":            "Wird überprüft…",
		"prism_why_intro":      "Loupe hat ungewöhnlichen Datenverkehr aus Ihrem Netzwerk festgestellt und möchte sicherstellen, dass diese Anfragen von einem Menschen und nicht von einem Programm stammen. Wenn Sie das Puzzle lösen, gelangen Sie weiter zur Website.",
		"prism_why_list_intro": "Das kann passieren, wenn:",
		"prism_why_lists":      "Ihre IP-Adresse auf öffentlichen Listen von Adressen steht, die mit Missbrauch in Verbindung gebracht werden,",
		"prism_why_vpn":        "Sie ein VPN, einen Proxy oder das Netzwerk eines Hosting-Anbieters nutzen,",
		"prism_why_network":    "andere Geräte in Ihrem Netzwerk viele automatisierte Anfragen gesendet haben oder",
		"prism_why_ext":        "eine Browsererweiterung oder ein Skript Anfragen für Sie sendet.",
		"prism_why_after":      "Nachdem Sie die Überprüfung bestanden haben, werden Sie eine Weile nicht mehr gefragt. Wenn Sie diese Seite immer wieder sehen, sendet möglicherweise noch ein Gerät oder eine Erweiterung in Ihrem Netzwerk automatisierten Datenverkehr.",

		"unverified_status": "Ihr Browser konnte nicht überprüft werden.",
		"unverified_before": "Eine Einstellung oder Erweiterung in Ihrem Browser blockiert oder verändert, was Loupe prüft, zum Beispiel deaktiviertes JavaScript oder deaktivierte Cookies, Fingerprinting-Schutz oder einen User-Agent-Switcher. Bitte deaktivieren Sie sie für diese Website und",
		"try_again":         "versuchen Sie es erneut",
		"unverified_after":  ".",

		"verdict_id":     "Verdict-ID:",
		"your_ip":        "Ihre IP:",
		"reveal":         "Zum Anzeigen klicken",
		"reveal_aria":    "Ihre IP-Adresse anzeigen",
		"secured_before": "Geschützt durch Loupe von ",
		"secured_after":  ".",
	},

	"fr": {
		"title_checking":   "Loupe — Vérification de votre navigateur",
		"title_verify":     "Loupe — Vérification",
		"title_blocked":    "Loupe — Accès refusé",
		"title_unverified": "Loupe — Vérification impossible",

		"checking":               "Vérification de votre navigateur",
		"checking_sub_challenge": "Loupe vérifie que vous êtes un humain.<br>Cela ne prend généralement qu’un instant.",
		"checking_sub_pulse":     "Cela ne prendra qu’un instant.",
		"verify_heading":         "Veuillez confirmer pour continuer.",
		"i_am_human":             "Je suis humain",
		"progress_label":         "Progression de la vérification",
		"verified":               "Vérifié !",
		"redirecting":            "Redirection vers le site ...",
		"failed":                 `La vérification a échoué. <a href="">Actualisez la page</a> pour réessayer.`,

		"why": "Pourquoi cette page s’affiche-t-elle ?",

		"blocked_status":         "Désolé, votre accès a été bloqué.",
		"blocked_sub":            "Loupe n’a pas pu vérifier la légitimité de votre trafic.<br>Si vous pensez qu’il s’agit d’une erreur, veuillez contacter le propriétaire du site.",
		"blocked_why_intro":      "Ce site utilise Loupe pour se protéger du trafic automatisé. Votre requête a été bloquée parce qu’elle provenait d’un réseau, d’une adresse IP ou d’un logiciel qui semblait automatisé, ou parce que plusieurs tentatives de vérification ont échoué d’affilée.",
		"blocked_why_list_intro": "Cela peut arriver même si vous n’avez rien fait de mal :",
		"blocked_why_shared":     "<strong>Réseaux partagés.</strong> Une autre personne sur votre Wi-Fi, votre réseau de bureau, d’école ou mobile, ou sur votre VPN ou proxy, a peut-être envoyé ce trafic.",
		"blocked_why_vpn":        "<strong>VPN, proxys et hébergeurs.</strong> Les adresses de ces services sont souvent utilisées de manière abusive et inspirent donc moins confiance.",
		"blocked_why_ext":        "<strong>Extensions de navigateur ou scripts</strong> qui envoient des requêtes automatiquement ou modifient la façon dont votre navigateur s’identifie.",
		"blocked_why_todo":       "<strong>Que faire :</strong> attendez un moment puis réessayez, car certains blocages sont levés automatiquement. Vous pouvez aussi changer de réseau, par exemple en désactivant votre VPN ou en utilisant les données mobiles au lieu du Wi-Fi. Si le blocage persiste, contactez le propriétaire du site en indiquant l’<strong>ID de verdict</strong> affiché ci-dessous afin qu’il puisse le retrouver.",
		"title_ratelimited":      "Loupe — Trop de requêtes",
		"ratelimited_status":     "Vos requêtes sont temporairement limitées.",
		"ratelimited_sub":        "Trop de requêtes ont été envoyées depuis votre connexion en peu de temps.<br>Veuillez patienter un instant, puis réessayer.",
		"ratelimited_wait":       "Vous pourrez réessayer dans {n} secondes.",
		"ratelimited_ready":      "Vous pouvez réessayer maintenant.",
		"ratelimited_retry":      "Réessayer",
		"ratelimited_why":        "Le propriétaire de ce site limite le nombre de requêtes que chaque visiteur peut effectuer en peu de temps, afin que le site reste rapide et sûr. Cela peut aussi arriver à de vraies personnes, par exemple après avoir rechargé une page de nombreuses fois, ou lorsque beaucoup de personnes partagent un même réseau, bureau ou VPN. La limite se lève d’elle-même : il suffit d’attendre.",

		"prism_status":         "Faites glisser la pièce dans l’emplacement correspondant pour continuer.",
		"prism_error":          "Mauvais emplacement — veuillez réessayer.",
		"prism_loading":        "Chargement du puzzle…",
		"prism_loading_new":    "Chargement d’un nouveau puzzle…",
		"continue":             "Continuer →",
		"verifying":            "Vérification…",
		"prism_why_intro":      "Loupe a détecté un trafic inhabituel provenant de votre réseau et souhaite s’assurer que ces requêtes sont envoyées par une personne et non par un programme. Résoudre le puzzle vous permet de continuer vers le site.",
		"prism_why_list_intro": "Cela peut arriver lorsque :",
		"prism_why_lists":      "votre adresse IP figure sur des listes publiques d’adresses associées à des abus,",
		"prism_why_vpn":        "vous utilisez un VPN, un proxy ou le réseau d’un hébergeur,",
		"prism_why_network":    "d’autres appareils de votre réseau ont envoyé de nombreuses requêtes automatisées, ou",
		"prism_why_ext":        "une extension de navigateur ou un script envoie des requêtes à votre place.",
		"prism_why_after":      "Une fois la vérification réussie, elle ne vous sera plus demandée pendant un certain temps. Si cette page s’affiche sans cesse, un appareil ou une extension de votre réseau envoie peut-être encore du trafic automatisé.",

		"unverified_status": "Votre navigateur n’a pas pu être vérifié.",
		"unverified_before": "Un paramètre ou une extension de votre navigateur bloque ou modifie ce que Loupe vérifie, par exemple JavaScript ou les cookies désactivés, une protection contre le fingerprinting ou un changeur d’user-agent. Veuillez le désactiver pour ce site, puis",
		"try_again":         "réessayez",
		"unverified_after":  ".",

		"verdict_id":     "ID de verdict :",
		"your_ip":        "Votre IP :",
		"reveal":         "Cliquez pour afficher",
		"reveal_aria":    "Afficher votre adresse IP",
		"secured_before": "Protégé par Loupe d’",
		"secured_after":  ".",
	},

	"es": {
		"title_checking":   "Loupe — Comprobando tu navegador",
		"title_verify":     "Loupe — Verificación",
		"title_blocked":    "Loupe — Acceso denegado",
		"title_unverified": "Loupe — No se pudo verificar",

		"checking":               "Comprobando tu navegador",
		"checking_sub_challenge": "Loupe está verificando que eres una persona.<br>Normalmente solo tarda un momento.",
		"checking_sub_pulse":     "Solo tardará un momento.",
		"verify_heading":         "Verifica para continuar.",
		"i_am_human":             "Soy una persona",
		"progress_label":         "Progreso de la verificación",
		"verified":               "¡Verificado!",
		"redirecting":            "Redirigiendo al sitio ...",
		"failed":                 `La verificación ha fallado. <a href="">Recarga la página</a> para intentarlo de nuevo.`,

		"why": "¿Por qué veo esta página?",

		"blocked_status":         "Lo sentimos, se ha bloqueado tu acceso.",
		"blocked_sub":            "Loupe no ha podido verificar la legitimidad de tu tráfico.<br>Si crees que se trata de un error, ponte en contacto con el propietario del sitio web.",
		"blocked_why_intro":      "Este sitio web usa Loupe para protegerse del tráfico automatizado. Tu solicitud se ha bloqueado porque procedía de una red, una dirección IP o un software que parecía automatizado, o porque hubo varios intentos de verificación fallidos seguidos.",
		"blocked_why_list_intro": "Esto puede ocurrir aunque no hayas hecho nada malo:",
		"blocked_why_shared":     "<strong>Redes compartidas.</strong> Puede que otra persona en tu Wi-Fi, en la red de tu oficina, centro educativo o móvil, o en tu VPN o proxy, haya enviado ese tráfico.",
		"blocked_why_vpn":        "<strong>VPN, proxies y proveedores de alojamiento.</strong> Las direcciones de estos servicios se usan a menudo de forma abusiva, por lo que reciben menos confianza.",
		"blocked_why_ext":        "<strong>Extensiones del navegador o scripts</strong> que envían solicitudes automáticamente o cambian cómo se identifica tu navegador.",
		"blocked_why_todo":       "<strong>Qué puedes hacer:</strong> espera un rato y vuelve a intentarlo, ya que algunos bloqueos se levantan solos. También puedes cambiar de red, por ejemplo desactivando tu VPN o usando datos móviles en lugar de Wi-Fi. Si el bloqueo continúa, ponte en contacto con el propietario del sitio web e incluye el <strong>ID de veredicto</strong> que aparece abajo para que pueda consultarlo.",
		"title_ratelimited":      "Loupe — Demasiadas solicitudes",
		"ratelimited_status":     "Tus solicitudes se están limitando.",
		"ratelimited_sub":        "Se enviaron demasiadas solicitudes desde tu conexión en poco tiempo.<br>Espera un momento y vuelve a intentarlo.",
		"ratelimited_wait":       "Podrás volver a intentarlo en {n} segundos.",
		"ratelimited_ready":      "Ya puedes volver a intentarlo.",
		"ratelimited_retry":      "Reintentar",
		"ratelimited_why":        "El propietario de este sitio web limita cuántas solicitudes puede hacer cada visitante en poco tiempo, para que el sitio siga siendo rápido y seguro. También les puede pasar a personas reales, por ejemplo, después de recargar una página muchas veces o cuando muchas personas comparten una misma red, oficina o VPN. El límite desaparece por sí solo, así que solo tienes que esperar.",

		"prism_status":         "Arrastra la pieza al hueco correspondiente para continuar.",
		"prism_error":          "Posición incorrecta. Inténtalo de nuevo.",
		"prism_loading":        "Cargando puzle…",
		"prism_loading_new":    "Cargando un puzle nuevo…",
		"continue":             "Continuar →",
		"verifying":            "Verificando…",
		"prism_why_intro":      "Loupe ha detectado tráfico inusual procedente de tu red y quiere asegurarse de que estas solicitudes las envía una persona y no un programa. Al resolver el puzle podrás continuar al sitio.",
		"prism_why_list_intro": "Esto puede ocurrir cuando:",
		"prism_why_lists":      "tu dirección IP aparece en listas públicas de direcciones relacionadas con abusos,",
		"prism_why_vpn":        "usas una VPN, un proxy o la red de un proveedor de alojamiento,",
		"prism_why_network":    "otros dispositivos de tu red han enviado muchas solicitudes automatizadas, o",
		"prism_why_ext":        "una extensión del navegador o un script está enviando solicitudes por ti.",
		"prism_why_after":      "Una vez que la superes, no se te volverá a pedir durante un tiempo. Si sigues viendo esta página, puede que algún dispositivo o extensión de tu red siga enviando tráfico automatizado.",

		"unverified_status": "No se ha podido verificar tu navegador.",
		"unverified_before": "Un ajuste o una extensión de tu navegador está bloqueando o modificando lo que comprueba Loupe, como JavaScript o las cookies desactivados, la protección contra fingerprinting o un cambiador de user-agent. Desactívalo para este sitio y",
		"try_again":         "vuelve a intentarlo",
		"unverified_after":  ".",

		"verdict_id":     "ID de veredicto:",
		"your_ip":        "Tu IP:",
		"reveal":         "Haz clic para mostrarla",
		"reveal_aria":    "Mostrar tu dirección IP",
		"secured_before": "Protegido por Loupe de ",
		"secured_after":  ".",
	},

	"it": {
		"title_checking":   "Loupe — Verifica del browser",
		"title_verify":     "Loupe — Verifica",
		"title_blocked":    "Loupe — Accesso negato",
		"title_unverified": "Loupe — Verifica non riuscita",

		"checking":               "Verifica del browser in corso",
		"checking_sub_challenge": "Loupe sta verificando che tu sia una persona.<br>Di solito ci vuole solo un momento.",
		"checking_sub_pulse":     "Ci vorrà solo un momento.",
		"verify_heading":         "Conferma per continuare.",
		"i_am_human":             "Sono un essere umano",
		"progress_label":         "Avanzamento della verifica",
		"verified":               "Verificato!",
		"redirecting":            "Reindirizzamento al sito ...",
		"failed":                 `Verifica non riuscita. <a href="">Ricarica la pagina</a> per riprovare.`,

		"why": "Perché vedo questa pagina?",

		"blocked_status":         "Spiacenti, il tuo accesso è stato bloccato.",
		"blocked_sub":            "Loupe non è riuscito a verificare la legittimità del tuo traffico.<br>Se ritieni che si tratti di un errore, contatta il proprietario del sito.",
		"blocked_why_intro":      "Questo sito usa Loupe per proteggersi dal traffico automatizzato. La tua richiesta è stata bloccata perché proveniva da una rete, un indirizzo IP o un software che sembrava automatizzato, oppure perché ci sono stati diversi tentativi di verifica falliti di seguito.",
		"blocked_why_list_intro": "Può succedere anche se non hai fatto nulla di sbagliato:",
		"blocked_why_shared":     "<strong>Reti condivise.</strong> Qualcun altro sulla tua rete Wi-Fi, dell’ufficio, della scuola o mobile, oppure sulla tua VPN o proxy, potrebbe aver inviato quel traffico.",
		"blocked_why_vpn":        "<strong>VPN, proxy e provider di hosting.</strong> Gli indirizzi di questi servizi vengono spesso usati in modo improprio, quindi ricevono meno fiducia.",
		"blocked_why_ext":        "<strong>Estensioni del browser o script</strong> che inviano richieste automaticamente o cambiano il modo in cui il tuo browser si identifica.",
		"blocked_why_todo":       "<strong>Cosa puoi fare:</strong> attendi un po’ e riprova, perché alcuni blocchi si rimuovono da soli. Puoi anche cambiare rete, ad esempio disattivando la VPN o usando i dati mobili invece del Wi-Fi. Se il blocco continua, contatta il proprietario del sito indicando l’<strong>ID verdetto</strong> mostrato qui sotto, così potrà verificarlo.",
		"title_ratelimited":      "Loupe — Troppe richieste",
		"ratelimited_status":     "Le tue richieste sono temporaneamente limitate.",
		"ratelimited_sub":        "Dalla tua connessione sono arrivate troppe richieste in poco tempo.<br>Attendi un momento, poi riprova.",
		"ratelimited_wait":       "Potrai riprovare tra {n} secondi.",
		"ratelimited_ready":      "Ora puoi riprovare.",
		"ratelimited_retry":      "Riprova",
		"ratelimited_why":        "Il proprietario di questo sito limita quante richieste ogni visitatore può fare in poco tempo, per mantenere il sito veloce e sicuro. Può succedere anche a persone reali, ad esempio dopo aver ricaricato una pagina molte volte o quando molte persone condividono la stessa rete, lo stesso ufficio o la stessa VPN. Il limite si rimuove da solo: basta attendere.",

		"prism_status":         "Trascina il pezzo nello spazio corrispondente per continuare.",
		"prism_error":          "Posizione errata — riprova.",
		"prism_loading":        "Caricamento del puzzle…",
		"prism_loading_new":    "Caricamento di un nuovo puzzle…",
		"continue":             "Continua →",
		"verifying":            "Verifica in corso…",
		"prism_why_intro":      "Loupe ha rilevato traffico insolito dalla tua rete e vuole assicurarsi che queste richieste vengano inviate da una persona e non da un programma. Risolvendo il puzzle potrai continuare sul sito.",
		"prism_why_list_intro": "Può succedere quando:",
		"prism_why_lists":      "il tuo indirizzo IP compare in elenchi pubblici di indirizzi associati ad abusi,",
		"prism_why_vpn":        "usi una VPN, un proxy o la rete di un provider di hosting,",
		"prism_why_network":    "altri dispositivi sulla tua rete hanno inviato molte richieste automatizzate, oppure",
		"prism_why_ext":        "un’estensione del browser o uno script sta inviando richieste al posto tuo.",
		"prism_why_after":      "Una volta superata la verifica, non ti verrà richiesta di nuovo per un po’. Se continui a vedere questa pagina, un dispositivo o un’estensione sulla tua rete potrebbe ancora inviare traffico automatizzato.",

		"unverified_status": "Non è stato possibile verificare il tuo browser.",
		"unverified_before": "Un’impostazione o un’estensione del tuo browser blocca o modifica ciò che Loupe controlla, ad esempio JavaScript o cookie disattivati, la protezione dal fingerprinting o un selettore di user-agent. Disattivala per questo sito, poi",
		"try_again":         "riprova",
		"unverified_after":  ".",

		"verdict_id":     "ID verdetto:",
		"your_ip":        "Il tuo IP:",
		"reveal":         "Fai clic per mostrarlo",
		"reveal_aria":    "Mostra il tuo indirizzo IP",
		"secured_before": "Protetto da Loupe di ",
		"secured_after":  ".",
	},

	"nl": {
		"title_checking":   "Loupe — Je browser wordt gecontroleerd",
		"title_verify":     "Loupe — Verificatie",
		"title_blocked":    "Loupe — Toegang geweigerd",
		"title_unverified": "Loupe — Verificatie niet mogelijk",

		"checking":               "Je browser wordt gecontroleerd",
		"checking_sub_challenge": "Loupe controleert of je een mens bent.<br>Dit duurt meestal maar even.",
		"checking_sub_pulse":     "Dit duurt maar even.",
		"verify_heading":         "Bevestig om door te gaan.",
		"i_am_human":             "Ik ben een mens",
		"progress_label":         "Voortgang van de verificatie",
		"verified":               "Geverifieerd!",
		"redirecting":            "Je wordt doorgestuurd naar de site ...",
		"failed":                 `Verificatie mislukt. <a href="">Vernieuw de pagina</a> om het opnieuw te proberen.`,

		"why": "Waarom zie ik deze pagina?",

		"blocked_status":         "Sorry, je bent geblokkeerd.",
		"blocked_sub":            "Loupe kon de legitimiteit van je verkeer niet bevestigen.<br>Denk je dat dit een vergissing is, neem dan contact op met de eigenaar van de website.",
		"blocked_why_intro":      "Deze website gebruikt Loupe om zich te beschermen tegen geautomatiseerd verkeer. Je verzoek is geblokkeerd omdat het afkomstig was van een netwerk, IP-adres of software die geautomatiseerd leek, of omdat er meerdere mislukte verificatiepogingen achter elkaar waren.",
		"blocked_why_list_intro": "Dit kan ook gebeuren als je niets verkeerd hebt gedaan:",
		"blocked_why_shared":     "<strong>Gedeelde netwerken.</strong> Iemand anders op je wifi, kantoor-, school- of mobiele netwerk, of op je VPN of proxy, kan het verkeer hebben verstuurd.",
		"blocked_why_vpn":        "<strong>VPN’s, proxy’s en hostingproviders.</strong> Adressen van deze diensten worden vaak misbruikt en krijgen daarom minder vertrouwen.",
		"blocked_why_ext":        "<strong>Browserextensies of scripts</strong> die automatisch verzoeken versturen of veranderen hoe je browser zich identificeert.",
		"blocked_why_todo":       "<strong>Wat je kunt doen:</strong> wacht even en probeer het opnieuw, want sommige blokkades worden vanzelf opgeheven. Je kunt ook van netwerk wisselen, bijvoorbeeld door je VPN uit te zetten of mobiele data te gebruiken in plaats van wifi. Blijft de blokkade bestaan, neem dan contact op met de eigenaar van de website en vermeld de <strong>Verdict-ID</strong> hieronder, zodat die kan worden opgezocht.",
		"title_ratelimited":      "Loupe — Te veel verzoeken",
		"ratelimited_status":     "Je verzoeken worden tijdelijk beperkt.",
		"ratelimited_sub":        "Er kwamen in korte tijd te veel verzoeken van je verbinding.<br>Wacht even en probeer het dan opnieuw.",
		"ratelimited_wait":       "Je kunt het over {n} seconden opnieuw proberen.",
		"ratelimited_ready":      "Je kunt het nu opnieuw proberen.",
		"ratelimited_retry":      "Opnieuw proberen",
		"ratelimited_why":        "De eigenaar van deze website beperkt hoeveel verzoeken elke bezoeker in korte tijd kan doen, zodat de site snel en veilig blijft. Dit kan ook echte mensen overkomen, bijvoorbeeld nadat je een pagina vaak hebt herladen, of als veel mensen hetzelfde netwerk, kantoor of dezelfde VPN delen. De beperking verdwijnt vanzelf, dus je hoeft alleen even te wachten.",

		"prism_status":         "Sleep het stukje naar de passende opening om door te gaan.",
		"prism_error":          "Verkeerde plek — probeer het opnieuw.",
		"prism_loading":        "Puzzel laden…",
		"prism_loading_new":    "Nieuwe puzzel laden…",
		"continue":             "Doorgaan →",
		"verifying":            "Bezig met verifiëren…",
		"prism_why_intro":      "Loupe heeft ongebruikelijk verkeer vanaf je netwerk opgemerkt en wil zeker weten dat deze verzoeken van een mens komen en niet van een programma. Als je de puzzel oplost, kun je doorgaan naar de site.",
		"prism_why_list_intro": "Dit kan gebeuren als:",
		"prism_why_lists":      "je IP-adres op openbare lijsten staat van adressen die met misbruik in verband worden gebracht,",
		"prism_why_vpn":        "je een VPN, een proxy of het netwerk van een hostingprovider gebruikt,",
		"prism_why_network":    "andere apparaten op je netwerk veel geautomatiseerde verzoeken hebben verstuurd, of",
		"prism_why_ext":        "een browserextensie of script namens jou verzoeken verstuurt.",
		"prism_why_after":      "Als je bent geslaagd, wordt het je een tijdje niet meer gevraagd. Blijf je deze pagina zien, dan verstuurt een apparaat of extensie op je netwerk mogelijk nog steeds geautomatiseerd verkeer.",

		"unverified_status": "Je browser kon niet worden geverifieerd.",
		"unverified_before": "Een instelling of extensie in je browser blokkeert of wijzigt wat Loupe controleert, zoals uitgeschakelde JavaScript of cookies, bescherming tegen fingerprinting of een user-agent-switcher. Zet deze uit voor deze site en",
		"try_again":         "probeer het opnieuw",
		"unverified_after":  ".",

		"verdict_id":     "Verdict-ID:",
		"your_ip":        "Je IP:",
		"reveal":         "Klik om te tonen",
		"reveal_aria":    "Je IP-adres tonen",
		"secured_before": "Beveiligd door Loupe van ",
		"secured_after":  ".",
	},

	"pt": {
		"title_checking":   "Loupe — Verificando seu navegador",
		"title_verify":     "Loupe — Verificação",
		"title_blocked":    "Loupe — Acesso negado",
		"title_unverified": "Loupe — Não foi possível verificar",

		"checking":               "Verificando seu navegador",
		"checking_sub_challenge": "O Loupe está verificando se você é humano.<br>Isso normalmente leva só um instante.",
		"checking_sub_pulse":     "Isso levará só um instante.",
		"verify_heading":         "Confirme para continuar.",
		"i_am_human":             "Sou uma pessoa",
		"progress_label":         "Progresso da verificação",
		"verified":               "Verificado!",
		"redirecting":            "Redirecionando para o site ...",
		"failed":                 `A verificação falhou. <a href="">Recarregue a página</a> para tentar novamente.`,

		"why": "Por que estou vendo esta página?",

		"blocked_status":         "Desculpe, seu acesso foi bloqueado.",
		"blocked_sub":            "O Loupe não conseguiu verificar a legitimidade do seu tráfego.<br>Se você acredita que isso é um erro, entre em contato com o responsável pelo site.",
		"blocked_why_intro":      "Este site usa o Loupe para se proteger de tráfego automatizado. Sua solicitação foi bloqueada porque veio de uma rede, um endereço IP ou um software que parecia automatizado, ou porque houve várias tentativas de verificação malsucedidas seguidas.",
		"blocked_why_list_intro": "Isso pode acontecer mesmo que você não tenha feito nada de errado:",
		"blocked_why_shared":     "<strong>Redes compartilhadas.</strong> Outra pessoa no seu Wi-Fi, na rede do escritório, da escola ou móvel, ou na sua VPN ou proxy, pode ter enviado o tráfego.",
		"blocked_why_vpn":        "<strong>VPNs, proxies e provedores de hospedagem.</strong> Endereços desses serviços são frequentemente usados de forma abusiva e, por isso, recebem menos confiança.",
		"blocked_why_ext":        "<strong>Extensões do navegador ou scripts</strong> que enviam solicitações automaticamente ou mudam a forma como o seu navegador se identifica.",
		"blocked_why_todo":       "<strong>O que você pode fazer:</strong> aguarde um pouco e tente novamente, pois alguns bloqueios são removidos automaticamente. Você também pode trocar de rede, por exemplo desativando sua VPN ou usando dados móveis em vez de Wi-Fi. Se o bloqueio continuar, entre em contato com o responsável pelo site e informe o <strong>ID do veredito</strong> mostrado abaixo para que ele possa ser consultado.",
		"title_ratelimited":      "Loupe — Muitas solicitações",
		"ratelimited_status":     "Suas solicitações estão sendo limitadas.",
		"ratelimited_sub":        "Muitas solicitações vieram da sua conexão em pouco tempo.<br>Aguarde um momento e tente novamente.",
		"ratelimited_wait":       "Você poderá tentar novamente em {n} segundos.",
		"ratelimited_ready":      "Você já pode tentar novamente.",
		"ratelimited_retry":      "Tentar novamente",
		"ratelimited_why":        "O responsável por este site limita quantas solicitações cada visitante pode fazer em pouco tempo, para manter o site rápido e seguro. Isso também pode acontecer com pessoas reais, por exemplo depois de recarregar uma página muitas vezes ou quando muitas pessoas compartilham a mesma rede, escritório ou VPN. O limite é removido sozinho, então basta esperar.",

		"prism_status":         "Arraste a peça até o espaço correspondente para continuar.",
		"prism_error":          "Posição incorreta — tente novamente.",
		"prism_loading":        "Carregando quebra-cabeça…",
		"prism_loading_new":    "Carregando novo quebra-cabeça…",
		"continue":             "Continuar →",
		"verifying":            "Verificando…",
		"prism_why_intro":      "O Loupe detectou tráfego incomum vindo da sua rede e quer ter certeza de que é uma pessoa, e não um programa, que está enviando essas solicitações. Ao resolver o quebra-cabeça, você poderá continuar para o site.",
		"prism_why_list_intro": "Isso pode acontecer quando:",
		"prism_why_lists":      "seu endereço IP aparece em listas públicas de endereços associados a abusos,",
		"prism_why_vpn":        "você está usando uma VPN, um proxy ou a rede de um provedor de hospedagem,",
		"prism_why_network":    "outros dispositivos na sua rede enviaram muitas solicitações automatizadas, ou",
		"prism_why_ext":        "uma extensão do navegador ou um script está enviando solicitações por você.",
		"prism_why_after":      "Depois de passar, você não será solicitado novamente por um tempo. Se continuar vendo esta página, algum dispositivo ou extensão na sua rede pode ainda estar enviando tráfego automatizado.",

		"unverified_status": "Não foi possível verificar seu navegador.",
		"unverified_before": "Uma configuração ou extensão do seu navegador está bloqueando ou alterando o que o Loupe verifica, como JavaScript ou cookies desativados, proteção contra fingerprinting ou um alternador de user-agent. Desative-a para este site e",
		"try_again":         "tente novamente",
		"unverified_after":  ".",

		"verdict_id":     "ID do veredito:",
		"your_ip":        "Seu IP:",
		"reveal":         "Clique para mostrar",
		"reveal_aria":    "Mostrar seu endereço IP",
		"secured_before": "Protegido pelo Loupe da ",
		"secured_after":  ".",
	},

	"pl": {
		"title_checking":   "Loupe — Sprawdzanie przeglądarki",
		"title_verify":     "Loupe — Weryfikacja",
		"title_blocked":    "Loupe — Odmowa dostępu",
		"title_unverified": "Loupe — Nie można zweryfikować",

		"checking":               "Sprawdzanie przeglądarki",
		"checking_sub_challenge": "Loupe sprawdza, czy jesteś człowiekiem.<br>Zwykle trwa to tylko chwilę.",
		"checking_sub_pulse":     "To potrwa tylko chwilę.",
		"verify_heading":         "Potwierdź, aby kontynuować.",
		"i_am_human":             "Jestem człowiekiem",
		"progress_label":         "Postęp weryfikacji",
		"verified":               "Zweryfikowano!",
		"redirecting":            "Przekierowywanie do witryny ...",
		"failed":                 `Weryfikacja nie powiodła się. <a href="">Odśwież stronę</a>, aby spróbować ponownie.`,

		"why": "Dlaczego widzę tę stronę?",

		"blocked_status":         "Przepraszamy, dostęp został zablokowany.",
		"blocked_sub":            "Loupe nie mógł potwierdzić wiarygodności Twojego ruchu.<br>Jeśli uważasz, że to błąd, skontaktuj się z właścicielem witryny.",
		"blocked_why_intro":      "Ta witryna używa Loupe do ochrony przed zautomatyzowanym ruchem. Twoje żądanie zostało zablokowane, ponieważ pochodziło z sieci, adresu IP lub oprogramowania, które wyglądały na zautomatyzowane, albo ponieważ kilka prób weryfikacji z rzędu zakończyło się niepowodzeniem.",
		"blocked_why_list_intro": "Może się to zdarzyć bez żadnej winy z Twojej strony:",
		"blocked_why_shared":     "<strong>Sieci współdzielone.</strong> Ruch mógł wysłać ktoś inny w Twojej sieci Wi-Fi, firmowej, szkolnej lub komórkowej albo korzystający z tego samego VPN lub proxy.",
		"blocked_why_vpn":        "<strong>VPN, proxy i dostawcy hostingu.</strong> Adresy tych usług są często nadużywane, dlatego cieszą się mniejszym zaufaniem.",
		"blocked_why_ext":        "<strong>Rozszerzenia przeglądarki lub skrypty</strong>, które automatycznie wysyłają żądania lub zmieniają sposób, w jaki przeglądarka się przedstawia.",
		"blocked_why_todo":       "<strong>Co możesz zrobić:</strong> odczekaj chwilę i spróbuj ponownie, ponieważ niektóre blokady znikają same. Możesz też zmienić sieć, na przykład wyłączając VPN lub korzystając z danych komórkowych zamiast Wi-Fi. Jeśli blokada nie ustąpi, skontaktuj się z właścicielem witryny i podaj widoczny poniżej <strong>identyfikator werdyktu</strong>, aby mógł go sprawdzić.",
		"title_ratelimited":      "Loupe — Zbyt wiele żądań",
		"ratelimited_status":     "Twoje żądania są tymczasowo ograniczone.",
		"ratelimited_sub":        "Z Twojego połączenia wysłano zbyt wiele żądań w krótkim czasie.<br>Odczekaj chwilę i spróbuj ponownie.",
		"ratelimited_wait":       "Możesz spróbować ponownie za {n} s.",
		"ratelimited_ready":      "Możesz już spróbować ponownie.",
		"ratelimited_retry":      "Spróbuj ponownie",
		"ratelimited_why":        "Właściciel tej witryny ogranicza liczbę żądań, które każdy odwiedzający może wysłać w krótkim czasie, aby witryna pozostała szybka i bezpieczna. Może się to zdarzyć także prawdziwym osobom, na przykład po wielokrotnym odświeżaniu strony lub gdy wiele osób korzysta z tej samej sieci, biura lub VPN. Ograniczenie znika samo, wystarczy chwilę poczekać.",

		"prism_status":         "Przeciągnij element do pasującego miejsca, aby kontynuować.",
		"prism_error":          "Nieprawidłowe miejsce — spróbuj ponownie.",
		"prism_loading":        "Ładowanie układanki…",
		"prism_loading_new":    "Ładowanie nowej układanki…",
		"continue":             "Dalej →",
		"verifying":            "Weryfikowanie…",
		"prism_why_intro":      "Loupe wykrył nietypowy ruch z Twojej sieci i chce się upewnić, że te żądania wysyła człowiek, a nie program. Rozwiązanie układanki pozwoli Ci przejść do witryny.",
		"prism_why_list_intro": "Może się to zdarzyć, gdy:",
		"prism_why_lists":      "Twój adres IP znajduje się na publicznych listach adresów powiązanych z nadużyciami,",
		"prism_why_vpn":        "korzystasz z VPN, proxy lub sieci dostawcy hostingu,",
		"prism_why_network":    "inne urządzenia w Twojej sieci wysłały wiele zautomatyzowanych żądań lub",
		"prism_why_ext":        "rozszerzenie przeglądarki lub skrypt wysyła żądania w Twoim imieniu.",
		"prism_why_after":      "Po pomyślnej weryfikacji przez jakiś czas nie zobaczysz jej ponownie. Jeśli ta strona wciąż się pojawia, jakieś urządzenie lub rozszerzenie w Twojej sieci może nadal wysyłać zautomatyzowany ruch.",

		"unverified_status": "Nie udało się zweryfikować przeglądarki.",
		"unverified_before": "Ustawienie lub rozszerzenie przeglądarki blokuje lub zmienia to, co sprawdza Loupe, na przykład wyłączony JavaScript lub pliki cookie, ochrona przed fingerprintingiem albo przełącznik user-agenta. Wyłącz je dla tej witryny, a następnie",
		"try_again":         "spróbuj ponownie",
		"unverified_after":  ".",

		"verdict_id":     "ID werdyktu:",
		"your_ip":        "Twój IP:",
		"reveal":         "Kliknij, aby pokazać",
		"reveal_aria":    "Pokaż swój adres IP",
		"secured_before": "Chronione przez Loupe firmy ",
		"secured_after":  ".",
	},

	"ja": {
		"title_checking":   "Loupe — ブラウザを確認しています",
		"title_verify":     "Loupe — 確認",
		"title_blocked":    "Loupe — アクセスが拒否されました",
		"title_unverified": "Loupe — 確認できません",

		"checking":               "ブラウザを確認しています",
		"checking_sub_challenge": "Loupe があなたが人間であることを確認しています。<br>通常はすぐに終わります。",
		"checking_sub_pulse":     "すぐに終わります。",
		"verify_heading":         "続行するには確認してください。",
		"i_am_human":             "私は人間です",
		"progress_label":         "確認の進行状況",
		"verified":               "確認しました！",
		"redirecting":            "サイトへ移動しています ...",
		"failed":                 `確認に失敗しました。<a href="">ページを再読み込み</a>してもう一度お試しください。`,

		"why": "このページが表示される理由",

		"blocked_status":         "申し訳ありませんが、アクセスがブロックされました。",
		"blocked_sub":            "Loupe はあなたのトラフィックの正当性を確認できませんでした。<br>誤りだと思われる場合は、ウェブサイトの管理者にお問い合わせください。",
		"blocked_why_intro":      "このウェブサイトは Loupe を使って自動化されたトラフィックから保護されています。リクエストが自動化されているように見えるネットワーク、IP アドレス、またはソフトウェアから送信されたか、確認の失敗が連続したため、ブロックされました。",
		"blocked_why_list_intro": "何も悪いことをしていなくても、次のような場合に起こることがあります。",
		"blocked_why_shared":     "<strong>共有ネットワーク。</strong>同じ Wi-Fi、職場・学校・モバイルのネットワーク、または同じ VPN やプロキシを使っている別の人がトラフィックを送信した可能性があります。",
		"blocked_why_vpn":        "<strong>VPN、プロキシ、ホスティング事業者。</strong>これらのサービスのアドレスは悪用されることが多いため、信頼度が低くなります。",
		"blocked_why_ext":        "<strong>ブラウザ拡張機能やスクリプト</strong>が自動的にリクエストを送信したり、ブラウザの識別情報を変更したりしている場合。",
		"blocked_why_todo":       "<strong>対処方法：</strong>ブロックの中には自動的に解除されるものもあるため、しばらく待ってからもう一度お試しください。VPN をオフにする、Wi-Fi の代わりにモバイルデータを使うなど、ネットワークを切り替えることもできます。ブロックが続く場合は、下に表示されている<strong>判定 ID</strong> を添えてウェブサイトの管理者にお問い合わせください。",
		"title_ratelimited":      "Loupe — リクエストが多すぎます",
		"ratelimited_status":     "リクエストが一時的に制限されています。",
		"ratelimited_sub":        "お使いの接続から短時間に多くのリクエストが送信されました。<br>しばらく待ってから、もう一度お試しください。",
		"ratelimited_wait":       "{n} 秒後に再試行できます。",
		"ratelimited_ready":      "再試行できるようになりました。",
		"ratelimited_retry":      "再試行",
		"ratelimited_why":        "このウェブサイトの所有者は、サイトを高速かつ安全に保つため、各訪問者が短時間に送信できるリクエストの数を制限しています。ページを何度も再読み込みした場合や、多くの人が同じネットワーク、オフィス、VPN を共有している場合など、実際の人にも起こることがあります。制限は自動的に解除されるので、しばらくお待ちください。",

		"prism_status":         "続行するには、ピースを合う場所までドラッグしてください。",
		"prism_error":          "位置が正しくありません。もう一度お試しください。",
		"prism_loading":        "パズルを読み込んでいます…",
		"prism_loading_new":    "新しいパズルを読み込んでいます…",
		"continue":             "続行 →",
		"verifying":            "確認しています…",
		"prism_why_intro":      "Loupe があなたのネットワークから通常とは異なるトラフィックを検出したため、これらのリクエストがプログラムではなく人によって送信されていることを確認しようとしています。パズルを解くとサイトに進めます。",
		"prism_why_list_intro": "次のような場合に表示されることがあります。",
		"prism_why_lists":      "あなたの IP アドレスが、不正利用に関係するアドレスの公開リストに載っている",
		"prism_why_vpn":        "VPN、プロキシ、またはホスティング事業者のネットワークを使っている",
		"prism_why_network":    "同じネットワーク上の他の端末が自動化されたリクエストを大量に送信した",
		"prism_why_ext":        "ブラウザ拡張機能やスクリプトがあなたの代わりにリクエストを送信している",
		"prism_why_after":      "一度確認を通過すると、しばらくは再度求められません。このページが何度も表示される場合は、ネットワーク上の端末や拡張機能がまだ自動化されたトラフィックを送信している可能性があります。",

		"unverified_status": "ブラウザを確認できませんでした。",
		"unverified_before": "JavaScript や Cookie の無効化、フィンガープリント対策、ユーザーエージェントの切り替えなど、ブラウザの設定や拡張機能が Loupe の確認をブロックまたは変更しています。このサイトではそれをオフにしてから、",
		"try_again":         "もう一度お試しください",
		"unverified_after":  "。",

		"verdict_id":     "判定 ID：",
		"your_ip":        "あなたの IP：",
		"reveal":         "クリックして表示",
		"reveal_aria":    "IP アドレスを表示",
		"secured_before": "",
		"secured_after":  "の Loupe により保護されています。",
	},

	"zh": {
		"title_checking":   "Loupe — 正在检查您的浏览器",
		"title_verify":     "Loupe — 验证",
		"title_blocked":    "Loupe — 访问被拒绝",
		"title_unverified": "Loupe — 无法验证",

		"checking":               "正在检查您的浏览器",
		"checking_sub_challenge": "Loupe 正在验证您是否为真人。<br>通常只需片刻。",
		"checking_sub_pulse":     "只需片刻。",
		"verify_heading":         "请完成验证以继续。",
		"i_am_human":             "我是真人",
		"progress_label":         "验证进度",
		"verified":               "验证成功！",
		"redirecting":            "正在跳转到网站 ...",
		"failed":                 `验证失败。请<a href="">刷新页面</a>后重试。`,

		"why": "为什么会看到此页面？",

		"blocked_status":         "抱歉，您的访问已被阻止。",
		"blocked_sub":            "Loupe 无法确认您的流量是否合法。<br>如果您认为这是误判，请联系网站所有者。",
		"blocked_why_intro":      "本网站使用 Loupe 防范自动化流量。您的请求被阻止，是因为它来自看起来像自动化程序的网络、IP 地址或软件，或者因为连续多次验证失败。",
		"blocked_why_list_intro": "即使您没有做错任何事，也可能出现这种情况：",
		"blocked_why_shared":     "<strong>共享网络。</strong>与您使用同一 Wi-Fi、办公、学校或移动网络，或同一 VPN 或代理的其他人可能发送了这些流量。",
		"blocked_why_vpn":        "<strong>VPN、代理和托管服务商。</strong>这些服务的地址经常被滥用，因此信任度较低。",
		"blocked_why_ext":        "<strong>浏览器扩展或脚本</strong>自动发送请求，或更改了浏览器的身份标识。",
		"blocked_why_todo":       "<strong>您可以这样做：</strong>稍等片刻后重试，部分封禁会自动解除。您也可以切换网络，例如关闭 VPN，或改用移动数据而不是 Wi-Fi。如果仍被阻止，请联系网站所有者，并提供下方显示的<strong>判定 ID</strong>，以便对方查询。",
		"title_ratelimited":      "Loupe — 请求过多",
		"ratelimited_status":     "您的请求已被暂时限制。",
		"ratelimited_sub":        "您的连接在短时间内发送了过多请求。<br>请稍等片刻，然后重试。",
		"ratelimited_wait":       "您可以在 {n} 秒后重试。",
		"ratelimited_ready":      "您现在可以重试了。",
		"ratelimited_retry":      "重试",
		"ratelimited_why":        "本网站的所有者限制了每位访问者在短时间内可以发出的请求数量，以保持网站快速、安全。真实用户也可能遇到这种情况，例如多次刷新页面后，或许多人共用同一网络、办公室或 VPN 时。限制会自动解除，您只需稍等片刻。",

		"prism_status":         "请将拼图块拖到匹配的缺口处以继续。",
		"prism_error":          "位置不正确，请重试。",
		"prism_loading":        "正在加载拼图…",
		"prism_loading_new":    "正在加载新拼图…",
		"continue":             "继续 →",
		"verifying":            "正在验证…",
		"prism_why_intro":      "Loupe 检测到来自您网络的异常流量，需要确认这些请求是由真人而不是程序发出的。完成拼图后即可继续访问网站。",
		"prism_why_list_intro": "出现这种情况的原因可能是：",
		"prism_why_lists":      "您的 IP 地址出现在与滥用行为相关的公开地址列表中；",
		"prism_why_vpn":        "您正在使用 VPN、代理或托管服务商的网络；",
		"prism_why_network":    "您网络中的其他设备发送了大量自动化请求；或",
		"prism_why_ext":        "某个浏览器扩展或脚本正在代您发送请求。",
		"prism_why_after":      "验证通过后，一段时间内不会再次要求验证。如果您反复看到此页面，可能是您网络中的某台设备或某个扩展仍在发送自动化流量。",

		"unverified_status": "无法验证您的浏览器。",
		"unverified_before": "您浏览器中的某项设置或扩展正在阻止或更改 Loupe 的检查内容，例如禁用了 JavaScript 或 Cookie、启用了指纹防护，或使用了 User-Agent 切换器。请为本网站关闭该设置，然后",
		"try_again":         "重试",
		"unverified_after":  "。",

		"verdict_id":     "判定 ID：",
		"your_ip":        "您的 IP：",
		"reveal":         "点击显示",
		"reveal_aria":    "显示您的 IP 地址",
		"secured_before": "由 ",
		"secured_after":  " 的 Loupe 提供保护。",
	},
}

// locales pairs each language's strings with its <html lang> value.
var locales = func() map[string]locale {
	tags := map[string]string{"zh": "zh-Hans"}
	m := make(map[string]locale, len(messages))
	for k, t := range messages {
		lang := k
		if tag, ok := tags[k]; ok {
			lang = tag
		}
		m[k] = locale{Lang: lang, T: t}
	}
	return m
}()
