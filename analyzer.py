import re
import httpx
import asyncio
from urllib.parse import urlparse, urljoin


class SiteAnalyzer:
    """
    Elite-level site fingerprinting engine.
    Scans homepage + auto-discovered pages for payment gateways,
    security layers, CAPTCHAs, CMS platforms, and hosting intel.
    """

    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        ]

        # detection limits (keep fast / safe)
        self.MAX_JS_SCRIPTS = 10
        self.MAX_JS_BYTES = 250_000
        self.MAX_PROBE_URLS = 120
        self.MAX_SITEMAP_URLS = 250
        self.MAX_EXPOSURE_CHECKS = 6

        # ── Gateway Signatures (STRICT / DEEP) ───────────────────
        self.GATEWAY_SIGNATURES = {
            "WooCommerce Payments": [
                r"woocommerce-payments",
                r"woocommerce_payments",
                r"wc-woopayments",
                r"wcpay",
                r"wcpay-payment-request",
                r"wcpay-card",
            ],
            "PayPal (WooCommerce/Commerce)": [
                r"woocommerce-paypal-payments",
                r"ppcp",
                r"paypal-payments",
                r"pymntpl-paypal",
                r"paypal\.com/sdk/js",
                r"paypalobjects\.com",
                r"paypal\.Buttons",
            ],
            "Stripe (WooCommerce)": [
                r"woocommerce-gateway-stripe",
                r"wc_stripe",
                r"wc-stripe",
                r"stripe\.com",
                r"js\.stripe\.com",
            ],
            "Razorpay": [
                r"razorpay\.com",
                r"checkout\.razorpay",
                r"rzp_live",
                r"rzp_test",
                r"razorpay-payment-button",
                r"Razorpay\(",
            ],
            "Paystack": [
                r"paystack\.co",
                r"js\.paystack\.co",
                r"paystackpop",
                r"paystack-inline",
            ],
            "Flutterwave": [
                r"flutterwave",
                r"checkout\.flutterwave\.com",
                r"ravepay",
                r"flw\.PBFKey",
            ],
            "Mollie": [
                r"mollie\.com",
                r"js\.mollie\.com",
                r"mollieProfileId",
            ],
            "Klarna": [
                r"klarna\.com",
                r"klarnacdn\.net",
                r"Klarna\.Payments",
                r"klarna-payments-sdk",
            ],
            "Afterpay": [
                r"afterpay\.com",
                r"js\.afterpay\.com",
                r"afterpay-widget",
            ],
            "Affirm": [
                r"affirm\.com",
                r"cdn1\.affirm\.com",
                r"_affirm_config",
            ],
            "Coinbase Commerce": [
                r"commerce\.coinbase\.com",
                r"coinbase-commerce",
                r"coinbaseCommerce",
            ],
            "Shopify Payments": [
                r"cdn\.shopify\.com",
                r"shopify_payments",
                r"Shopify\.Pay",
                r"/checkouts/",
                r"/cart\.js",
                r"/payments/config",
                r"shopify-checkout",
            ],
            "PayU": [
                r"payu\.in",
                r"payu\.com",
                r"payumoney",
                r"payubiz",
                r"secure\.payu",
                r"payu_hash",
            ],
            "Cashfree": [
                r"cashfree\.com",
                r"sdk\.cashfree",
                r"cashfree-checkout",
            ],
            "Instamojo": [
                r"instamojo\.com",
                r"js\.instamojo",
                r"Instamojo",
            ],
            "CCAvenue": [
                r"ccavenue",
                r"secure\.ccavenue",
                r"payment\.ccavenue",
            ],
            "Paytm": [
                r"paytm",
                r"securegw\.paytm",
                r"paytm\.com",
            ],
            "PhonePe": [
                r"phonepe",
                r"api\.phonepe",
                r"phonepe\.com",
            ],
            "Juspay": [
                r"juspay",
                r"hypercheckout",
                r"api\.juspay",
            ],
            "Midtrans": [
                r"midtrans",
                r"snap\.midtrans",
                r"app\.midtrans",
            ],
            "Xendit": [
                r"xendit",
                r"xendit\.co",
                r"js\.xendit",
            ],
            "iZettle / Zettle": [
                r"zettle",
                r"izettle",
            ],
            "iDEAL": [
                r"ideal",
                r"mollie.*ideal",
                r"adyen.*ideal",
            ],
            "Mercado Pago": [
                r"mercadopago",
                r"mp\.com",
                r"checkout\.mercadopago",
            ],
            "PagSeguro": [
                r"pagseguro",
                r"uol\.com\.br/pagseguro",
            ],
            "PayFast": [
                r"payfast",
                r"payfast\.co\.za",
            ],
            "PayTR": [
                r"paytr",
                r"paytr\.com",
            ],
            "iyzico": [
                r"iyzico",
                r"iyzipay",
                r"js\.iyzico",
            ],
            "Skrill": [
                r"skrill",
                r"pay\.skrill",
            ],
            "Neteller": [
                r"neteller",
            ],
            "Wise": [
                r"wise\.com",
                r"transferwise",
            ],
            "Payoneer": [
                r"payoneer",
            ],
            "Payeer": [
                r"payeer",
            ],
            "GPay / Google Pay": [
                r"pay\.google\.com",
                r"google\.payments\.api",
                r"gpay",
                r"GooglePayButton",
            ],
            "Apple Pay": [
                r"ApplePaySession",
                r"apple-pay",
                r"apple-pay-button",
            ],
            "Stripe": [
                r"js\.stripe\.com",
                r"stripe[\-_]?v3",
                r"Stripe\s*\(",
                r"stripe\.elements",
                r"stripe\.checkout",
                r"stripe\.redirectToCheckout",
                r"pk_live_",
                r"pk_test_",
                r"stripe-button",
                r"StripeCheckout\.configure",
                r"stripe\.createToken",
                r"stripe\.createPaymentMethod",
                r"stripe\.confirmCardPayment",
                r"stripe-payment-element",
                r"__stripe_mid",
                r"__stripe_sid",
                r"stripe\.handleCardAction",
                r"data-stripe",
                r"stripe-card-element",
                r"payment_intent_client_secret",
                r"stripe_publishable_key",
                r"m\.stripe\.com",
                r"r\.stripe\.com",
                r"hooks\.stripe\.com",
                r"stripejs\.com",
                r"stripe-js",
                r"StripeElement",
                r'name="stripeToken"',
                r'id="stripe-token"',
                r'class="StripeElement"',
            ],
            "Braintree": [
                r"braintree[\-_]web",
                r"braintree\.js",
                r"api\.braintreegateway",
                r"braintree\.client\.create",
                r"braintree\.dropin",
                r"braintree-hosted-fields",
                r"client\.tokenizeCard",
                r"data-braintree",
                r"braintree\.hostedFields",
                r"braintree\.paypal",
                r"braintree\.threeDSecure",
                r"braintree\.applePay",
                r"braintree\.googlePayment",
                r"assets\.braintreegateway\.com",
                r"braintree_client_token",
                r"payments\.braintree-api\.com",
                r"braintree-dropin",
                r"braintree\.venmo",
                r"braintree\.dataCollector",
                r"braintree-web-drop-in",
                r"dropin\.create",
                r"BraintreeError",
                r'name="payment_method_nonce"',
                r'class="braintree-hosted-field"',
            ],
            "Authorize.Net": [
                r"authorize\.net",
                r"Accept\.js",
                r"AcceptUI",
                r"authnet",
                r"accept\.authorize\.net",
                r"api\.authorize\.net",
                r"anet_cust_id",
                r"securePaymentContainerRequest",
                r"authorizenet\.com",
                r"AcceptUI\.openButton",
                r"AuthorizeNetPopup",
                r"opaqueData",
                r"dataDescriptor",
                r"dataValue",
                r"authnet_nonce",
                r"authnet_data_descriptor",
                r"jstest\.authorize\.net",
                r"js\.authorize\.net",
                r"responseHandler.*Accept",
                r"dispatchData.*authorize",
                r"payment_method.*authnet",
                r"wc-authnet",
                r"authorize-net",
                r'name="dataDescriptor"',
                r'name="dataValue"',
            ],
            "Chase/Paymentech": [
                r"chase\.com/payment",
                r"paymentech",
                r"orbital\.com",
                r"securepayments\.chase\.com",
                r"chase-paymentech",
                r"orbital-gateway",
                r"chase\.merchant",
                r"ChasePaymentech",
                r"orbitalgateway",
                r"chase_merchant_id",
            ],
            "Square": [
                r"squareup\.com",
                r"sq-payment",
                r"square[\-_]elements",
                r"web\.squarecdn\.com",
                r"square\.js",
                r"SqPaymentForm",
                r"square-web-sdk",
                r"squareup\.com/js/sq",
                r"square\.payments",
                r"sq-card",
                r"sq-apple-pay",
                r"sq-google-pay",
                r"square-marketplace",
                r"connect\.squareup",
                r"square_application_id",
            ],
            "Adyen": [
                r"adyen\.com",
                r"adyencheckout",
                r"checkoutshopper[\-_]live",
                r"adyen\.encrypt",
                r"adyen-checkout",
                r"AdyenCheckout",
                r"adyen\.cse",
                r"adyen-encrypted-data",
                r"adyen\.createComponent",
                r"checkoutshopper-test\.adyen",
                r"adyen-web",
                r"adyen_merchant",
                r"adyenjs",
                r"adyen\.com/checkoutshopper",
            ],
            "CyberSource": [
                r"cybersource\.com",
                r"flex\.cybersource",
                r"flex/v2/tokens",
                r"microform\.js",
                r"sonypaymentservices",
                r"CyberSource\.Flex",
                r"cybersource-flex",
                r"cybersource\.microform",
                r"secureacceptance\.cybersource",
                r"testsecureacceptance\.cybersource",
                r"token\.cybersource\.com",
                r"cybersource_merchant",
            ],
            "Worldpay": [
                r"worldpay\.com",
                r"worldpay\.js",
                r"access\.worldpay",
                r"payments\.worldpay",
                r"worldpay-hosted",
                r"Worldpay\.useTemplateForm",
                r"Worldpay\.setupForm",
                r"worldpay-cse",
                r"secure\.worldpay",
                r"online\.worldpay",
                r"worldpay_merchant",
                r"fisglobal\.com/worldpay",
            ],
            "PayPal": [
                r"paypal\.com/sdk/js",
                r"paypalobjects\.com",
                r"paypal[\-_]checkout",
                r"paypal\.Buttons",
                r"paypal\.FUNDING",
                r"data-paypal-button",
                r"paypal-checkout-sdk",
                r"paypal\.com/cgi-bin/webscr",
                r"paypal\.com/xclick",
                r"paypal-express",
                r"paypal-smart-buttons",
                r"paypal\.CardFields",
                r"paypal\.HostedFields",
                r"paypal\.Marks",
                r"payflow",
                r"payflowlink",
                r"payflowpro",
                r"paypal-hosted-fields",
            ],
            "Eway": [
                r"eway\.com",
                r"eway\.io",
                r"eWAY[\s\-]?Rapid",
                r"secure\.ewaypayments",
                r"eway-hosted",
                r"eWAYECRypt",
                r"eway\.createClient",
                r"eCrypt\.js",
                r"myeway\.com",
                r"api\.ewaypayments",
                r"rapid-api",
                r"eway_merchant",
            ],
            "Clover": [
                r"clover\.com",
                r"clover-hosted",
                r"clover[\-_]sdk",
                r"api\.clover\.com",
                r"clover\.iframe",
                r"clover\.elements",
                r"clover-hosted-iframe",
                r"CloverCordova",
                r"clover_merchant",
                r"sandbox\.dev\.clover",
                r"token\.clover\.com",
            ],
            "PayU": [
                r"payu\.com",
                r"payu\.in",
                r"payumoney",
                r"payu[\-_]biz",
                r"secure\.payu",
                r"payulatam",
                r"payu\.co",
                r"PayUCheckout",
                r"payu-form",
                r"test\.payu\.in",
                r"payu\.global",
                r"payuasia",
                r"payubiz",
                r"payU_hash",
            ],
            "Elavon": [
                r"elavon\.com",
                r"converge\.elavon",
                r"gateway\.elavon",
                r"elavon\.converge",
                r"hosted\.elavon",
                r"demo\.elavon",
                r"converge-embedded",
                r"elavon_merchant",
            ],
            "NMI": [
                r"secure\.networkmerchants",
                r"nmi\.com",
                r"collect\.js",
                r"CollectJS\.configure",
                r"gateway\.transact\.com",
                r"secure\.nmi\.com",
                r"networkmerchants\.com",
                r"CollectJS\.startPaymentRequest",
                r"tokenization-key",
                r"collect-js-sdk",
                r"nmi_tokenization",
            ],
            "Moneris": [
                r"moneris\.com",
                r"esqa\.moneris",
                r"hpp\.moneris",
                r"gw\.moneris",
                r"MonerisCheckout",
                r"moneris-checkout",
                r"mpgGlobals",
                r"monerisjs",
                r"moneris\.hpp",
            ],
            "2Checkout/Verifone": [
                r"2checkout\.com",
                r"verifone\.com",
                r"2co\.com",
                r"avangate\.com",
                r"2Checkout\.js",
                r"TwoCoInlineCart",
                r"2co-inline",
                r"2payjs\.com",
                r"verifone2co",
            ],
            "BlueSnap": [
                r"bluesnap\.com",
                r"bluesnap\.js",
                r"sandbox\.bluesnap",
                r"pay\.bluesnap\.com",
                r"BlueSnapHostedPayment",
                r"bluesnap-token",
                r"bluesnap-hosted-fields",
            ],
            "Mollie": [
                r"mollie\.com",
                r"js\.mollie\.com",
                r"mollie-payments",
                r"mollie\.createComponent",
                r"api\.mollie\.com",
                r"mollie-checkout",
                r"mollieProfileId",
            ],
            "Razorpay": [
                r"razorpay\.com",
                r"checkout\.razorpay",
                r"rzp_live",
                r"rzp_test",
                r"Razorpay\(",
                r"razorpay\.open",
                r"razorpay-payment-button",
                r"razorpay\.createPayment",
            ],
            "Checkout.com": [
                r"checkout\.com",
                r"cdn\.checkout\.com",
                r"Checkout\.js",
                r"checkout-frames",
                r"checkout_sdk",
            ],
            "Paddle": [
                r"paddle\.com",
                r"cdn\.paddle\.com",
                r"Paddle\.Setup",
                r"paddle-checkout",
                r"paddle\.js",
            ],
            "Gumroad": [r"gumroad\.com", r"gumroad\.js", r"gumroad-checkout"],
            "LemonSqueezy": [
                r"lemonsqueezy\.com",
                r"lemonsqueezy\.js",
                r"lemonsqueezy-checkout",
            ],
            "Paysafe": [
                r"paysafe\.com",
                r"paysafe\.js",
                r"paysafecard",
                r"api\.paysafe\.com",
                r"hosted\.paysafe",
                r"paysafe-checkout",
                r"paysafe-threedsecure",
            ],
            "Bambora": [
                r"bambora\.com",
                r"na\.bambora",
                r"web\.na\.bambora",
                r"bambora-checkout",
                r"BamboraCheckout",
                r"customcheckout\.bambora",
                r"bambora\.customcheckout",
            ],
            "USAePay": [
                r"usaepay\.com",
                r"sandbox\.usaepay",
                r"secure\.usaepay",
                r"USAePay\.Client",
                r"usaepayjs",
            ],
            "Heartland": [
                r"heartlandportico",
                r"globalpaymentsinc\.com",
                r"hps\.js",
                r"HeartlandHPS",
                r"heartland\.securesubmit",
                r"api\.heartlandportico",
                r"secure\.heartlandpayment",
                r"securesubmit\.js",
                r"Heartland\.Card",
            ],
            "WePay": [
                r"wepay\.com",
                r"wepay\.js",
                r"WePay\.iframe_checkout",
                r"stage\.wepay\.com",
                r"wepay-widget",
            ],
            "Amazon Pay": [
                r"amazonpay",
                r"amazon-pay",
                r"pay\.amazon",
                r"static-na\.payments-amazon",
                r"OffAmazonPayments",
                r"amazon-payments",
                r"amzn\.payments",
            ],
            "Apple Pay": [
                r"apple-pay-button",
                r"ApplePaySession",
                r"canMakePayments.*apple",
                r"apple-pay-logo",
                r"supports.*applePay",
            ],
            "Google Pay": [
                r"google-pay-button",
                r"GooglePayButton",
                r"pay\.google\.com",
                r"google\.payments\.api",
                r"isReadyToPay.*google",
                r"gpay-button",
            ],
            "Klarna": [
                r"klarna\.com",
                r"klarna\.payments",
                r"Klarna\.Payments",
                r"x\.klarnacdn\.net",
                r"klarna-payments-sdk",
                r"klarna-checkout",
                r"klarnacdn\.net",
            ],
            "Afterpay": [
                r"afterpay\.com",
                r"afterpay\.js",
                r"afterpay-widget",
                r"portal\.afterpay",
                r"js\.afterpay\.com",
            ],
            "Sezzle": [
                r"sezzle\.com",
                r"sezzle\.js",
                r"widget\.sezzle",
                r"sezzle-checkout",
                r"sezzle-smart-widget",
            ],
            "Affirm": [
                r"affirm\.com",
                r"affirm\.js",
                r"cdn1\.affirm\.com",
                r"affirm-checkout",
                r"_affirm_config",
            ],
            "Windcave/PaymentExpress": [
                r"windcave\.com",
                r"paymentexpress\.com",
                r"sec\.windcave",
                r"dps\.net\.nz",
                r"paymentexpress\.hosted",
            ],
            "Opayo/SagePay": [
                r"opayo\.co\.uk",
                r"sagepay\.com",
                r"pi-live\.sagepay",
                r"pi-test\.sagepay",
                r"SagePay\.Direct",
                r"opayo-form",
                r"sagepay-direct",
            ],
            "Recurly": [
                r"recurly\.com",
                r"recurly\.js",
                r"js\.recurly\.com",
                r"recurly\.configure",
                r"recurly-element",
                r"data-recurly",
            ],
            "Chargebee": [
                r"chargebee\.com",
                r"js\.chargebee\.com",
                r"Chargebee\.init",
                r"chargebee-checkout",
                r"cbInstance",
            ],
            "CardConnect": [
                r"cardconnect\.com",
                r"cardpointe",
                r"fts\.cardconnect",
                r"bolt\.cardconnect",
                r"CardSecure",
            ],
            "FluidPay": [
                r"fluidpay\.com",
                r"api\.fluidpay\.com",
                r"fluidpay-tokenizer",
                r"fluidpay\.js",
            ],
            "Payeezy/FirstData": [
                r"payeezy\.com",
                r"firstdata",
                r"api\.payeezy\.com",
                r"firstdata\.com",
                r"Payeezy\.doPayment",
                r"globalgatewaye4",
                r"e4transact",
            ],
        }

        # ── CMS Signatures (STRICT) ─────────────────────────────
        self.CMS_SIGNATURES = {
            "Shopify": [
                r"cdn\.shopify\.com",
                r"shopify\.com",
                r"Shopify\.theme",
                r"myshopify\.com",
                r"shopify-buy",
            ],
            "WooCommerce": [
                r"woocommerce",
                r"wc-ajax",
                r"wc_cart",
                r"wc-checkout",
                r"woocommerce-checkout",
                r"wc-add-to-cart",
            ],
            "BigCommerce": [r"bigcommerce\.com", r"cdn\.bigcommerce", r"stencil-utils"],
            "Magento": [r"magento", r"mage/cookies", r"Magento_", r"varien/js", r"magento\.com"],
            "PrestaShop": [r"prestashop", r"modules/ps_", r"presta\.com"],
            "OpenCart": [r"opencart", r"catalog/view/theme", r"route=checkout/checkout"],
            "WordPress": [r"wp-content", r"wp-includes", r"wp-json"],
            "Drupal Commerce": [r"drupal", r"drupal\.org", r"commerce-checkout"],
            "Zen Cart": [r"zen-cart", r"zencart", r"ipn_main_handler"],
            "osCommerce": [r"oscommerce", r"osc_session", r"tep_href_link"],
            "Volusion": [r"volusion\.com", r"cdn-volusion", r"a\.vimg\.net"],
            "Squarespace": [r"squarespace\.com", r"sqsp\.com", r"static\.squarespace"],
        }

        # ── CAPTCHA Signatures (ULTRA-ELITE / PASSIVE) ──────────
        self.CAPTCHA_SIGNATURES = {
            "reCAPTCHA v2": [
                r"google\.com/recaptcha/api\.js",
                r"g-recaptcha",
                r"data-sitekey",
                r"recaptcha/api2/",
                r"recaptcha-anchor",
            ],
            "reCAPTCHA v3/Enterprise": [
                r"recaptcha/api\.js\?render=",
                r"grecaptcha\.execute",
                r"recaptcha-v3",
                r"recaptcha\.enterprise",
                r"enterprise\.js",
                r"google\.com/recaptcha/enterprise",
            ],
            "hCaptcha": [
                r"hcaptcha\.com",
                r"h-captcha",
                r"data-hcaptcha",
                r"hcaptcha-response",
                r"api\.hcaptcha\.com",
                r"h-captcha-container",
                r"h_captcha",
                r'class=["\']h-captcha["\']',
                r'id=["\']h-captcha["\']',
                r"new\s*hcaptcha",
            ],
            "Cloudflare Turnstile": [
                r"challenges\.cloudflare\.com/turnstile",
                r"cf-turnstile",
                r"turnstile\.render",
                r"cf-chl-widget",
                r"turnstile-response",
            ],
            "DataDome": [
                r"dd_captcha",
                r"captcha-delivery\.com",
                r"datadome\.js",
                r"window\.ddjs",
                r"dd\.co/dd\.js",
            ],
            "FunCaptcha": [r"funcaptcha", r"arkoselabs", r"arkose-enforcement", r"api\.arkoselabs\.com"],
            "GeeTest": [r"geetest", r"gt\.js", r"initGeetest"],
            "Friendly Captcha/Altcha": [r"friendlycaptcha", r"frc-captcha", r"altcha"],
            "Cloudflare Captcha": [r"cf-captcha-container", r"cf-chl-widget", r"cf_captcha_kind"],
            "Generic Captcha": [
                r'class=["\']captcha["\']',
                r'id=["\']captcha["\']',
                r"__captcha",
                r"captcha-container",
                r'src=["\'][^"\']*captcha[^"\']*["\']',
                r"data-captcha",
            ],
        }

        # ── Checkout paths to probe ─────────────────────────────
        self.CHECKOUT_PATHS = [
            "/checkout",
            "/cart",
            "/basket",
            "/donate",
            "/give",
            "/pay",
            "/payment",
            "/purchase",
            "/order",
            "/billing",
            "/shop/checkout",
            "/store/checkout",
            "/wp-json/wc/store/cart",
            "/index.php/checkout",
            "/index.php?route=checkout/checkout",
            "/onepage",
            "/onestepcheckout",
            "/firecheckout",
            "/my-account",
            "/account",
            "/my-account/add-payment-method",
        ]

        # ── Key & Token Patterns ────────────────────────────────
        self.KEY_PATTERNS = {
            "Stripe Key": r"pk_(?:live|test)_[a-zA-Z0-9]{24,}",
            "reCAPTCHA Key": r'google\.com/recaptcha/api\.js\?render=([a-zA-Z0-9_\-]{40})|data-sitekey=["\']([a-zA-Z0-9_\-]{40})["\']',
            "hCaptcha Key": r'data-sitekey=["\']([a-f0-9\-]{36})["\']|([a-f0-9\-]{36}).*hcaptcha',
            "PayPal ID": r"client-id=([a-zA-Z0-9_\-]{50,})",
            "Braintree Key": r"production_[a-zA-Z0-9]{20,}|sandbox_[a-zA-Z0-9]{20,}",
            "Square ID": r"sq-application-id-([a-zA-Z0-9_\-]{20,})",
            "Turnstile Key": r'data-sitekey=["\'](0x[a-zA-Z0-9]{18,})["\']',
            "Paddle ID": r"Paddle\.Setup\(\{\s*vendor:\s*(\d+)",
        }

        # Potentially sensitive tokens (redacted in output)
        # These sometimes appear accidentally in frontend bundles.
        self.SENSITIVE_KEY_PATTERNS = {
            "Stripe Secret Key": r"\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b",
            "Stripe Webhook Secret": r"\bwhsec_[a-zA-Z0-9]{16,}\b",
            "AWS Access Key ID": r"\bAKIA[0-9A-Z]{16}\b",
            "Google API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
            "Firebase/FCM Server Key": r"\bAAAA[A-Za-z0-9_\-]{7,}:[A-Za-z0-9_\-]{100,}\b",
            "JWT": r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
            # Payment tokens (often should not be exposed client-side)
            "Braintree Client Token": r"\b(clientToken|authorization)\b[^\"']{0,30}[:=][^\"']{0,10}['\"]([A-Za-z0-9\-_]{80,})['\"]",
            "PayPal Client Token": r"\b(client-token|client_token)\b[^\"']{0,30}[:=][^\"']{0,10}['\"]([A-Za-z0-9\-_]{60,})['\"]",
            "Adyen Client Key": r"\bclientKey\b[^\"']{0,30}[:=][^\"']{0,10}['\"]([A-Za-z0-9]{16,})['\"]",
            "Adyen Checkoutshopper Token": r"\bcheckoutshopper\b[^\"']{0,60}['\"]([A-Za-z0-9\-_]{40,})['\"]",
            "Shopify Storefront Token": r"\b(storefrontAccessToken|x-shopify-storefront-access-token)\b[^\"']{0,60}['\"]([A-Za-z0-9\-_]{20,})['\"]",
            # Secrets dumped into HTML/JS
            "Env Secret (generic)": r"\b(API_KEY|SECRET|TOKEN|PRIVATE_KEY)\b\s*[:=]\s*['\"]([^'\"]{16,})['\"]",
            # Private key blocks
            "PEM Private Key": r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----[\s\S]{80,}?-----END (?:RSA |EC |)PRIVATE KEY-----",
            # Basic auth URLs
            "Basic Auth URL": r"https?://[^/\s:@]{1,128}:[^/\s@]{1,128}@[^\\s\"']+",
            # Cloud storage URLs that often indicate exposed buckets
            "AWS S3 Bucket URL": r"https?://[a-z0-9\.\-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[^\s\"']*",
            "GCS Bucket URL": r"https?://storage\.googleapis\.com/[a-z0-9\.\-_]{3,63}/[^\s\"']*",
            "Azure Blob URL": r"https?://[a-z0-9\-]{3,63}\.blob\.core\.windows\.net/[^\s\"']*",
            # More private key formats
            "OpenSSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{80,}?-----END OPENSSH PRIVATE KEY-----",
            "PGP Private Key": r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{80,}?-----END PGP PRIVATE KEY BLOCK-----",
        }

        # ── Keyword Gateway Catalog (broad fallback) ─────────────
        # Adds lightweight name-based detection for many processors.
        # This is intentionally less strict than the curated signatures above.
        self.BASE_GATEWAYS = [
            # ===== GLOBAL CARD PROCESSORS =====
            "Stripe", "PayPal", "Braintree", "Adyen", "Authorize.Net", "Square",
            "2Checkout", "Checkout.com", "Worldpay", "Cybersource", "BlueSnap",
            "NMI", "Mollie", "Spreedly", "TokenEx", "Nuvei", "Paysafe",

            # ===== US / CANADA =====
            "Shift4", "Cardconnect", "Heartland", "Global Payments", "TSYS",
            "Chase Paymentech", "Fiserv", "FreedomPay", "Elavon", "Moneris",
            "Paya", "Fortis", "Stax", "Payjunction", "Qualpay", "Helcim",
            "Clearent", "USAePay", "First Data", "Vantiv", "Repay",
            "Payrix", "Finix", "Tilled", "Gravity Payments", "Payarc",
            "Payline Data", "Basys", "National Processing", "PaymentCloud",
            "Element Payment", "Pivotal Payments", "Cayan", "ProPay",
            "Priority Commerce", "FlexPay", "Clover",

            # ===== EUROPE =====
            "Worldline", "Nexi", "SIX Payment", "Concardis", "Computop",
            "Unzer", "Heidelpay", "Wirecard", "Payone", "Ingenico",
            "Opayo", "Sage Pay", "Bambora", "Verifone", "Trust Payments",
            "Saferpay", "Datatrans", "Payrexx", "Viva Wallet", "EVO Payments",
            "Buckaroo", "MultiSafepay", "CCV", "Paysera", "Przelewy24",
            "Fondy", "Robokassa", "Cardstream", "Judopay", "DNA Payments",
            "Paymentsense", "Dojo", "PayVector", "Acquired.com",

            # ===== INDIA =====
            "Razorpay", "PayU", "Paytm", "Cashfree", "CCAvenue",
            "Billdesk", "Instamojo", "Zaakpay", "PayKun", "EaseBuzz",
            "Atom Technologies", "TechProcess", "Juspay", "Pine Labs",

            # ===== MIDDLE EAST =====
            "Tap Payments", "HyperPay", "PayTabs", "Telr", "Noon Payments",
            "Moyasar", "PayFort", "Amazon Payment Services", "Network International",
            "Magnati", "MyFatoorah", "Hesabe", "UPayments", "Fatora", "Thawani",

            # ===== AFRICA =====
            "Flutterwave", "Paystack", "Interswitch", "DPO Group",
            "PayGate", "PayFast", "Peach Payments", "Yoco", "Cellulant",
            "Korapay", "VoguePay",

            # ===== LATIN AMERICA =====
            "MercadoPago", "PagSeguro", "Cielo", "Rede", "Stone Pagamentos",
            "Pagar.me", "Getnet", "EBANX", "DLocal", "Kushki",
            "Conekta", "OpenPay Mexico", "PayRetailers", "ePayco", "Wompi",
            "PlacetoPay", "Transbank", "Webpay Plus", "Decidir",

            # ===== SOUTHEAST ASIA =====
            "Midtrans", "Xendit", "2C2P", "Omise", "HitPay",
            "iPay88", "eGHL", "Revenue Monster", "Senangpay", "Billplz",
            "PayMongo", "Dragonpay", "PesoPay",

            # ===== EAST ASIA =====
            "GMO Payment", "SB Payment Service", "Robot Payment", "Epsilon",
            "PayJP", "Komoju", "Zeus Payment", "Sony Payment Services",
            "NHN KCP", "INIpay", "KG Inicis", "Nice Payments", "Toss Payments",
            "Danal", "Settle Bank", "Smartro",

            # ===== AUSTRALIA / NZ =====
            "Eway", "Tyro", "Till Payments", "Windcave", "Fat Zebra",
            "Pin Payments", "SecurePay", "NAB Transact", "Paymark",

            # ===== PLATFORM PAYMENTS =====
            "Shopify Payments", "WooCommerce Payments", "Wix Payments",
            "Squarespace Payments", "BigCommerce Payments",

            # ===== AGGREGATORS / ORCHESTRATORS =====
            "Spreedly", "Corefy", "Akurateco", "PPRO", "Paymentwall",
            "Rapyd", "Airwallex",

            # ===== SUBSCRIPTION/RECURRING CARD BILLING =====
            "Recurly", "Chargebee", "Zuora", "Chargify", "Paddle",
            "FastSpring", "Vindicia", "Recharge Payments",
        ]

        # Track which gateways were added via keyword-only fallback
        self._keyword_added: set[str] = set()
        # Snapshot curated gateways before keyword expansion (for strict mode)
        self._curated_gateways: set[str] = set(self.GATEWAY_SIGNATURES.keys())
        self._add_keyword_gateway_signatures(self.BASE_GATEWAYS)
        self.GATEWAY_COUNT = len(self.GATEWAY_SIGNATURES)


    def _keyword_pattern(self, name: str) -> str:
        """
        Create a forgiving regex for a gateway name.
        Examples:
          "Authorize.Net" -> matches "authorize net", "authorize.net"
          "Payline Data"  -> matches "payline data", "payline-data"
        """
        n = (name or "").strip().lower()
        if not n:
            return ""
        # replace common separators with a flexible matcher
        n = n.replace("&", "and")
        # escape regex special chars, then loosen separators
        esc = re.escape(n)
        esc = esc.replace(r"\ ", r"[\s\-_]*")
        esc = esc.replace(r"\.", r"[\s\-_\.]*")
        return esc

    def _add_keyword_gateway_signatures(self, names: list[str]):
        """
        Add name-based gateway signatures for broad coverage.
        Does not override any existing curated entry in self.GATEWAY_SIGNATURES.
        """
        for raw in names:
            name = (raw or "").strip()
            if not name:
                continue
            if name in self.GATEWAY_SIGNATURES:
                continue
            pat = self._keyword_pattern(name)
            if not pat:
                continue
            # Word-boundary-ish wrapper to reduce random matches.
            self.GATEWAY_SIGNATURES[name] = [rf"(?:^|[^a-z0-9]){pat}(?:[^a-z0-9]|$)"]
            self._keyword_added.add(name)

    def _extract_attrs_and_actions(self, html: str) -> str:
        """Extract iframe/src, link/href, form/action, and data URLs for gateway matching."""
        try:
            t = html or ""
            found = []
            for m in re.findall(r'<iframe[^>]+src=["\'](.*?)["\']', t, flags=re.I):
                found.append(m)
            for m in re.findall(r'<form[^>]+action=["\'](.*?)["\']', t, flags=re.I):
                found.append(m)
            for m in re.findall(r'<link[^>]+href=["\'](.*?)["\']', t, flags=re.I):
                found.append(m)
            if not found:
                return ""
            return " " + " ".join(found[:200])
        except Exception:
            return ""

    def _extract_wc_settings_blob(self, text: str) -> str:
        """
        Best-effort extraction of WooCommerce 'wcSettings' / 'wc-settings' inline JSON-ish blobs.
        We don't fully parse JSON; we just pull nearby text for matching.
        """
        try:
            t = text or ""
            hits = []
            for m in re.finditer(r"(wcSettings|wc-settings)[\s\S]{0,2000}", t, flags=re.I):
                hits.append(m.group(0))
                if len(hits) >= 3:
                    break
            if not hits:
                return ""
            return " " + " ".join(hits)
        except Exception:
            return ""

    def _extract_tokenized_urls(self, text: str) -> list[str]:
        """Find URLs containing token/key/session/signature parameters (for redacted reporting)."""
        try:
            urls = re.findall(r"https?://[^\s\"'<>]+", text or "", flags=re.I)
            out = []
            for u in urls:
                if re.search(r"[\?&](token|key|signature|session|access_token|auth)=([^&]{6,})", u, flags=re.I):
                    out.append(u)
            return out[:40]
        except Exception:
            return []

    async def _check_common_exposures(self, client: httpx.AsyncClient, base: str) -> list[str]:
        """
        Low-impact exposure checks (report-only).
        Only a few GETs with short timeouts.
        """
        paths = [
            "/.env",
            "/.git/HEAD",
            "/.git/config",
            "/wp-config.php",
            "/composer.lock",
            "/.well-known/security.txt",
        ]
        findings = []
        for p in paths[: self.MAX_EXPOSURE_CHECKS]:
            try:
                url = base.rstrip("/") + p
                r = await client.get(url, timeout=5.0)
                if r.status_code == 200 and r.text and len(r.text) > 0:
                    # don't store body; just report that it's reachable
                    findings.append(f"Exposed file reachable: {p} (HTTP 200)")
            except Exception:
                continue
        return findings

    def _extract_script_srcs(self, html: str) -> str:
        """Return script src URLs concatenated for signature matching."""
        try:
            srcs = re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, flags=re.I)
            if not srcs:
                return ""
            return " ".join(srcs)
        except Exception:
            return ""

    def _extract_script_src_list(self, html: str) -> list[str]:
        """Extract a list of script src URLs (raw, may be relative)."""
        try:
            return re.findall(r'<script[^>]+src=["\'](.*?)["\']', html, flags=re.I)
        except Exception:
            return []

    def _extract_wc_gateway_slugs(self, text: str) -> str:
        """
        Extract WooCommerce gateway IDs from markup/JS and return as a single string.
        Common patterns:
          payment_method_stripe, payment_method_ppcp-gateway, etc.
        """
        try:
            t = text or ""
            slugs = set()
            for m in re.findall(r"\bpayment_method[_\-]([a-z0-9_\-]{2,64})\b", t, flags=re.I):
                slugs.add(m.lower())
            # Some themes expose gateway IDs in data attributes
            for m in re.findall(r"\bdata-payment-method=['\"]([a-z0-9_\-]{2,64})['\"]", t, flags=re.I):
                slugs.add(m.lower())
            if not slugs:
                return ""
            return " " + " ".join(sorted(slugs))
        except Exception:
            return ""

    def _extract_endpoint_hints(self, text: str) -> str:
        """
        Extract likely payment/checkout endpoints from HTML/JS text.
        This helps match gateways that only appear in XHR/fetch URLs.
        """
        try:
            t = text or ""
            hints = set()

            # Absolute URLs
            for u in re.findall(r"https?://[^\s\"'<>]+", t, flags=re.I):
                ul = u.lower()
                if any(k in ul for k in ("checkout", "payment", "pay", "gateway", "wc-ajax", "wc-api", "admin-ajax")):
                    hints.add(u)

            # Relative endpoints in JS (fetch("/..."), axios.post("/..."))
            for p in re.findall(r"['\"](/[^\"']{1,200})['\"]", t):
                pl = p.lower()
                if any(k in pl for k in ("checkout", "payment", "pay", "gateway", "wc-ajax", "wc-api", "admin-ajax", "paypal", "stripe", "adyen")):
                    hints.add(p)

            if not hints:
                return ""
            return " " + " ".join(list(hints)[:80])
        except Exception:
            return ""

    def _infer_likely_gateway(self, text: str) -> str:
        """
        Best-effort inference when only generic patterns match.
        Returns a short label like "Stripe (likely)" or "" if unknown.
        """
        t = (text or "").lower()
        rules = [
            ("Stripe (likely)", ["stripe", "js.stripe.com", "wc_stripe", "woocommerce-gateway-stripe", "payment_intent"]),
            ("PayPal (likely)", ["paypal", "ppcp", "paypalobjects.com", "paypal.com/sdk/js"]),
            ("WooCommerce Payments (likely)", ["woocommerce-payments", "wcpay", "wc-woopayments"]),
            ("Adyen (likely)", ["adyen", "checkoutshopper", "adyencheckout"]),
            ("Braintree (likely)", ["braintree", "braintreegateway", "client_token"]),
            ("Square (likely)", ["squareup", "squarecdn", "sq-payment", "sq0idp-"]),
            ("Razorpay (likely)", ["razorpay", "rzp_", "checkout.razorpay"]),
            ("Paystack (likely)", ["paystack", "paystackpop", "js.paystack.co"]),
            ("Flutterwave (likely)", ["flutterwave", "ravepay", "checkout.flutterwave"]),
            ("Mollie (likely)", ["mollie", "js.mollie.com"]),
            ("Klarna (likely)", ["klarna", "klarnacdn"]),
            ("Afterpay (likely)", ["afterpay", "js.afterpay.com"]),
            ("Affirm (likely)", ["affirm", "cdn1.affirm.com"]),
            ("Shopify Payments (likely)", ["shopify", "/checkouts/", "/cart.js", "shopify-checkout"]),
        ]
        for label, needles in rules:
            if any(n in t for n in needles):
                return label
        return ""

    def _infer_gateway_name(self, html: str, match_text: str) -> tuple[str, str]:
        """
        Try to infer an actual gateway name (not just Generic) from strong signals.
        Returns (gateway_name, confidence_level) or ("", "") if unknown.
        """
        h = (html or "").lower()
        t = (match_text or "").lower()

        # Strong WooCommerce gateway IDs (payment_method_*)
        slug_hits = set(re.findall(r"\bpayment_method[_\-]([a-z0-9_\-]{2,64})\b", t, flags=re.I))
        slug_map = {
            # Stripe
            "stripe": "Stripe",
            "wc_stripe": "Stripe",
            "woocommerce-gateway-stripe": "Stripe",
            # PayPal
            "paypal": "PayPal",
            "ppcp-gateway": "PayPal",
            "ppcp": "PayPal",
            "pymntpl-paypal": "PayPal",
            # WooCommerce Payments
            "woocommerce_payments": "WooCommerce Payments",
            "wcpay": "WooCommerce Payments",
            "wcpay_card": "WooCommerce Payments",
            # Adyen
            "adyen": "Adyen",
            # Razorpay / Paystack / Flutterwave
            "razorpay": "Razorpay",
            "paystack": "Paystack",
            "flutterwave": "Flutterwave",
            # Klarna / Afterpay / Affirm
            "klarna": "Klarna",
            "afterpay": "Afterpay",
            "affirm": "Affirm",
            # Mollie
            "mollie": "Mollie",
            # Square
            "square": "Square",
        }
        for s in slug_hits:
            gw = slug_map.get(s.lower())
            if gw:
                return gw, "Medium"

        # Strong host/script evidence (prefer over loose keyword hits)
        strong_rules = [
            ("Stripe", ["js.stripe.com", "hooks.stripe.com", "stripe.com/v3", "stripejs"]),
            ("PayPal", ["paypal.com/sdk/js", "paypalobjects.com", "www.paypal.com/cgi-bin/webscr"]),
            ("Braintree", ["braintreegateway.com", "assets.braintreegateway.com"]),
            ("Adyen", ["checkoutshopper", "adyen.com/checkoutshopper"]),
            ("Square", ["squareup.com", "squarecdn.com", "web.squarecdn.com"]),
            ("Razorpay", ["checkout.razorpay.com", "razorpay.com"]),
            ("Paystack", ["js.paystack.co", "paystack.co"]),
            ("Flutterwave", ["checkout.flutterwave.com", "flutterwave.com"]),
            ("Mollie", ["js.mollie.com", "mollie.com"]),
            ("Klarna", ["klarnacdn.net", "klarna.com"]),
            ("Afterpay", ["js.afterpay.com", "afterpay.com"]),
            ("Affirm", ["cdn1.affirm.com", "affirm.com"]),
            ("WooCommerce Payments", ["woocommerce-payments", "wcpay", "wc-woopayments"]),
            ("Shopify Payments", ["/checkouts/", "/cart.js", "/payments/config", "shopify-checkout"]),
            # Other processors with distinctive hostnames/paths
            ("2Checkout", ["2checkout.com", "2co.com", "2payjs.com"]),
            ("Checkout.com", ["checkout.com", "cdn.checkout.com"]),
            ("Worldpay", ["worldpay.com", "access.worldpay", "secure.worldpay"]),
            ("Cybersource", ["cybersource.com", "flex.cybersource", "secureacceptance.cybersource"]),
            ("Authorize.Net", ["accept.authorize.net", "js.authorize.net", "authorize.net"]),
            ("Paysafe", ["paysafe.com", "api.paysafe.com"]),
            ("Nuvei", ["nuvei", "safecharge", "api.nuvei"]),
            ("Skrill", ["skrill.com", "pay.skrill"]),
            ("Neteller", ["neteller.com"]),
            ("PayU", ["payu.in", "payu.com", "secure.payu"]),
            ("Cashfree", ["cashfree.com", "sdk.cashfree"]),
            ("Instamojo", ["instamojo.com", "js.instamojo"]),
            ("CCAvenue", ["ccavenue", "secure.ccavenue"]),
            ("Paytm", ["paytm", "securegw.paytm"]),
            ("Juspay", ["juspay", "hypercheckout"]),
            ("Midtrans", ["midtrans", "snap.midtrans"]),
            ("Xendit", ["xendit", "js.xendit"]),
            ("MercadoPago", ["mercadopago", "checkout.mercadopago"]),
            ("PagSeguro", ["pagseguro"]),
            ("PayFast", ["payfast.co.za", "payfast"]),
            ("PayTabs", ["paytabs", "paytabs.com"]),
            ("Telr", ["telr", "secure.telr"]),
            ("HyperPay", ["hyperpay", "oppwa.com"]),
            ("Tap Payments", ["tap.company", "tap-payments", "tap payments"]),
            ("MyFatoorah", ["myfatoorah"]),
            ("Thawani", ["thawani"]),
            ("Omise", ["omise", "omise.co"]),
            ("iPay88", ["ipay88"]),
            ("Billplz", ["billplz"]),
            ("HitPay", ["hitpay"]),
        ]
        for gw, needles in strong_rules:
            if any(n in t for n in needles):
                return gw, "High"

        # Shopify flow hints in HTML itself
        if "myshopify.com" in h and ("/checkouts/" in t or "/cart.js" in t):
            return "Shopify Payments", "Medium"

        return "", ""

    async def _discover_from_robots_and_sitemaps(
        self,
        client: httpx.AsyncClient,
        domain_base: str,
        checkout_keywords: str,
        max_urls: int = 200,
    ) -> list[str]:
        """
        Pull candidate checkout/account/cart URLs from robots.txt and sitemap.xml.
        Hard-limited for speed.
        """
        candidates: list[str] = []

        def add(u: str):
            if not u:
                return
            if len(candidates) >= max_urls:
                return
            candidates.append(u)

        # robots.txt
        try:
            r = await client.get(domain_base.rstrip("/") + "/robots.txt")
            if r.status_code == 200 and r.text:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.lower().startswith("sitemap:"):
                        sm = line.split(":", 1)[1].strip()
                        if sm:
                            add(sm)
        except Exception:
            pass

        # common sitemap locations + any from robots
        sitemap_urls = [
            domain_base.rstrip("/") + "/sitemap.xml",
            domain_base.rstrip("/") + "/sitemap_index.xml",
        ]
        for u in list(candidates):
            if u.lower().endswith(".xml"):
                sitemap_urls.append(u)

        seen = set()
        sitemap_urls = [u for u in sitemap_urls if not (u in seen or seen.add(u))]

        found_links: list[str] = []

        async def scan_sitemap(url: str):
            nonlocal found_links
            try:
                resp = await client.get(url)
                if resp.status_code != 200 or not resp.text:
                    return
                xml = resp.text
                # sitemap index
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml, flags=re.I):
                    if re.search(checkout_keywords, loc, re.I):
                        found_links.append(loc)
                    # follow a couple nested sitemaps
                    if loc.lower().endswith(".xml") and len(found_links) < 30:
                        try:
                            sub = await client.get(loc)
                            if sub.status_code == 200 and sub.text:
                                for loc2 in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sub.text, flags=re.I):
                                    if re.search(checkout_keywords, loc2, re.I):
                                        found_links.append(loc2)
                        except Exception:
                            pass
            except Exception:
                return

        # scan up to 3 sitemaps for speed
        for sm in sitemap_urls[:3]:
            await scan_sitemap(sm)

        # normalize
        normalized = []
        for u in found_links[:max_urls]:
            if u.startswith("http"):
                normalized.append(u)
            elif u.startswith("/"):
                normalized.append(domain_base.rstrip("/") + u)
        return normalized

    async def _fetch_script_bodies(
        self,
        client: httpx.AsyncClient,
        page_url: str,
        html: str,
        max_scripts: int = 8,
        max_bytes_per_script: int = 250_000,
        timeout_s: float = 6.0,
    ) -> str:
        """
        Deeper gateway detection:
        fetch a limited number of external JS files and return concatenated text.
        Hard limits keep this fast and prevent huge downloads.
        """
        srcs = self._extract_script_src_list(html)
        if not srcs:
            return ""

        # Prefer likely gateway-related JS by filename keywords.
        def score(u: str) -> int:
            ul = (u or "").lower()
            s = 0
            for k in (
                "checkout",
                "payment",
                "pay",
                "gateway",
                "stripe",
                "paypal",
                "braintree",
                "adyen",
                "klarna",
                "afterpay",
                "affirm",
                "woocommerce",
                "wcpay",
                "shopify",
            ):
                if k in ul:
                    s += 1
            return -s

        srcs = sorted(srcs, key=score)

        out = []
        used = 0
        for raw in srcs:
            if used >= max_scripts:
                break
            if not raw:
                continue
            full = urljoin(page_url, raw)
            # Skip obvious non-js
            if not re.search(r"\.js(\?|$)", full, re.I) and "javascript" not in full.lower():
                continue
            try:
                r = await client.get(full, timeout=timeout_s)
                if r.status_code != 200:
                    continue
                text = r.text
                if not text:
                    continue
                out.append(text[:max_bytes_per_script])
                used += 1
            except Exception:
                continue

        return "\n".join(out)

    def _client_kwargs(self, proxy: str | None):
        """
        Build kwargs for httpx.AsyncClient in a version-tolerant way.
        httpx has changed proxy args across versions (proxy vs proxies).
        """
        base = {
            "follow_redirects": True,
            "timeout": 15.0,
            "verify": False,
        }
        if not proxy:
            return base

        proxy_url = f"http://{proxy}"
        # Prefer newer-style `proxy=` first; fall back to older `proxies=`.
        try:
            httpx.AsyncClient(proxy=proxy_url, timeout=1.0)  # type: ignore[arg-type]
            base["proxy"] = proxy_url
            return base
        except TypeError:
            base["proxies"] = {"http://": proxy_url, "https://": proxy_url}
            return base

    async def analyze_site(self, url, proxy=None, strict: bool = False):
        """Main analysis entry point. Returns a dict of all findings."""
        results = {
            "gateway": "None Detected",
            "gateway_confidence": {},
            "strict_mode": bool(strict),
            "cms": "Unknown",
            "security": "None Detected",
            "captcha": "None Detected",
            "risk": "Low 🟢",
            "checkout_link": "Not Found",
            "keys": [],
            "privacy_findings": [],
            "intent": "Unknown",
            "lowest_price": "Unknown",
            "product_link": "None",
            "account_page": "None",
            "add_payment_link": "None",
            "status": "Success",
        }

        # Normalize URL
        if not url.startswith("http"):
            url = "https://" + url
        parsed = urlparse(url)
        domain_base = f"{parsed.scheme}://{parsed.netloc}"

        # Randomized Headers
        import random

        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        try:
            async with httpx.AsyncClient(headers=headers, **self._client_kwargs(proxy)) as client:
                response = await client.get(url)
                html = response.text
                resp_headers = response.headers
                resp_cookies = str(response.cookies)

                # Also scan script src URLs; many gateways load dynamically.
                src_blob = self._extract_script_srcs(html)
                attr_blob = self._extract_attrs_and_actions(html)
                wc_settings_blob = self._extract_wc_settings_blob(html)

                html_for_matching = html + " " + src_blob + " " + attr_blob + " " + wc_settings_blob

                # Deep scan: fetch a few JS bundles and scan their contents too.
                js_blob = await self._fetch_script_bodies(
                    client,
                    str(response.url),
                    html,
                    max_scripts=min(self.MAX_JS_SCRIPTS, 10),
                    max_bytes_per_script=self.MAX_JS_BYTES,
                )
                if js_blob:
                    html_for_matching += " " + js_blob
                # add extra hints from WooCommerce gateway IDs + endpoint URLs
                html_for_matching += self._extract_wc_gateway_slugs(html_for_matching)
                html_for_matching += self._extract_endpoint_hints(html_for_matching)

                # redacted tokenized URLs (for reporting)
                for u in self._extract_tokenized_urls(html_for_matching):
                    results["privacy_findings"].append(f"Tokenized URL (redacted): {self._redact_secret(u)}")

                # common exposure checks (report-only)
                results["privacy_findings"].extend(await self._check_common_exposures(client, domain_base))
        except Exception as e:
            results["status"] = f"Error: {str(e)}"
            return results

        # ── PHASE 2: Detect Gateways ────────────────────────────
        allowed_gateways = self._curated_gateways if strict else set(self.GATEWAY_SIGNATURES.keys())
        # Confidence scoring by source buckets
        match_sources = {
            "html": html,
            "attrs": attr_blob,
            "script_src": src_blob,
            "wc_settings": wc_settings_blob,
            "endpoints_and_slugs": self._extract_wc_gateway_slugs(html_for_matching) + " " + self._extract_endpoint_hints(html_for_matching),
            "js": js_blob or "",
        }

        all_found = set()
        confidence: dict[str, str] = {}

        def bump(gw: str, level: str):
            order = {"Low": 0, "Medium": 1, "High": 2}
            if gw not in confidence or order[level] > order.get(confidence[gw], 0):
                confidence[gw] = level

        for src_name, src_text in match_sources.items():
            if not src_text:
                continue
            found = self._match_signatures_allowed(src_text, self.GATEWAY_SIGNATURES, allowed_gateways)
            for gw in found:
                all_found.add(gw)
                # keyword-only gateways are always Low unless we see them in strong signals
                is_keyword_only = gw in getattr(self, "_keyword_added", set())
                if src_name in ("html", "script_src", "attrs", "js"):
                    bump(gw, "High" if not is_keyword_only else "Medium")
                elif src_name in ("endpoints_and_slugs", "wc_settings"):
                    bump(gw, "Medium" if not is_keyword_only else "Low")
                else:
                    bump(gw, "Low")

        gateways = sorted(all_found)
        results["gateway_confidence"] = confidence

        # STRICT MODE: only keep High confidence gateways (hard proof)
        if strict:
            gateways = [g for g in gateways if confidence.get(g) == "High"]
            results["gateway_confidence"] = {g: confidence.get(g, "High") for g in gateways}

        # Fallback: Detect Generic Gateways via keywords (disabled in strict mode)
        if (not strict) and (not gateways):
            generic_patterns = r"credit.card|visa|mastercard|amex|pay.with.card|payment.method|card.number|add.payment.method"
            if re.search(generic_patterns, html_for_matching, re.I):
                gateways = ["Generic / Private Gate 💳"]

        if gateways:
            results["gateway"] = ", ".join(f"{g}" if "💳" in g else f"{g} 💳" for g in gateways)

        # If only generic was detected, try to infer and promote a real gateway name.
        if (not strict) and results["gateway"] == "Generic / Private Gate 💳":
            gw_name, gw_conf = self._infer_gateway_name(html, html_for_matching)
            if gw_name:
                results["gateway"] = f"{gw_name} 💳"
                # also set confidence map if available
                if isinstance(results.get("gateway_confidence"), dict):
                    results["gateway_confidence"][gw_name] = gw_conf or "Medium"
            else:
                likely = self._infer_likely_gateway(html_for_matching)
                if likely:
                    results["gateway"] = f"{results['gateway']} ({likely})"

        # ── PHASE 3: Detect CMS ─────────────────────────────────
        cms_list = self._match_signatures(html, self.CMS_SIGNATURES)
        if cms_list:
            results["cms"] = ", ".join(f"{c} 🛒" for c in cms_list)

        # ── PHASE 4: Detect WAF / CDN / Security ────────────────
        security = self._detect_security(html, resp_headers, resp_cookies)
        if security:
            results["security"] = ", ".join(security)

        # ── PHASE 5: Detect CAPTCHAs ────────────────────────────
        captchas = self._match_signatures(html, self.CAPTCHA_SIGNATURES)
        if captchas:
            results["captcha"] = ", ".join(f"{c} 🤖" for c in captchas)

        # ── PHASE 6: Checkout Auto-Discovery (Deep Scan) ────────
        checkout_link, extra_gateways, extra_captchas = await self._discover_checkout(
            domain_base, html, proxy=proxy, headers=headers
        )
        if checkout_link:
            results["checkout_link"] = checkout_link
            # --- DEEP SCAN: Analyze the checkout page content ---
            try:
                async with httpx.AsyncClient(headers=headers, timeout=8.0, verify=False, **self._proxy_only_kwargs(proxy)) as client:
                    c_resp = await client.get(checkout_link)
                    c_html = c_resp.text
                    c_src_blob = self._extract_script_srcs(c_html)
                    c_attr_blob = self._extract_attrs_and_actions(c_html)
                    c_wc_settings_blob = self._extract_wc_settings_blob(c_html)
                    c_match_text = c_html + " " + c_src_blob + " " + c_attr_blob + " " + c_wc_settings_blob

                    c_js_blob = await self._fetch_script_bodies(client, str(c_resp.url), c_html, max_scripts=10, timeout_s=6.0)
                    if c_js_blob:
                        c_match_text += " " + c_js_blob
                    c_match_text += self._extract_wc_gateway_slugs(c_match_text)
                    c_match_text += self._extract_endpoint_hints(c_match_text)

                    # Look for gateways on checkout page
                    checkout_gateways = self._match_signatures(c_match_text, self.GATEWAY_SIGNATURES)
                    # Check for generic keywords on checkout page
                    if not checkout_gateways:
                        if re.search(
                            r"credit.card|visa|mastercard|amex|payment.method|card.number|billing.info|add.payment.method",
                            c_match_text,
                            re.I,
                        ):
                            checkout_gateways = ["Generic / Private Gate 💳"]

                    if checkout_gateways:
                        existing = set(gateways)
                        new_gw = [g for g in checkout_gateways if g not in existing]
                        if new_gw:
                            current = results["gateway"]
                            addition = ", ".join(f"{g}" if "💳" in g else f"{g} 💳" for g in new_gw)
                            results["gateway"] = f"{current}, {addition}" if current != "None Detected" else addition
            except Exception:
                pass

        if extra_captchas:
            existing_caps = set(captchas)
            new_caps = [c for c in extra_captchas if c not in existing_caps]
            if new_caps:
                current = results["captcha"]
                addition = ", ".join(f"{c} 🤖" for c in new_caps)
                results["captcha"] = f"{current}, {addition}" if current != "None Detected" else addition

        # ── PHASE 7: Key & Token Extraction ─────────────────────
        found_keys = self._extract_keys(html)
        if checkout_link:
            try:
                async with httpx.AsyncClient(headers=headers, timeout=5.0, verify=False, **self._proxy_only_kwargs(proxy)) as client:
                    c_resp = await client.get(checkout_link)
                    found_keys.extend(self._extract_keys(c_resp.text))
            except Exception:
                pass
        results["keys"] = list(set(found_keys))

        # ── PHASE 8: Intent Detection ───────────────────────────
        intent = "Charge 💰"
        technical_auth = r"setup_intent|requestPaymentMethod|submitForSettlement:\s*false|capture_method:\s*manual|authorize_only"
        auth_keywords = r"donate|give|membership|subscription|verify|validate|authorize|trial|save.card|free.trial"
        charge_keywords = r"buy.now|purchase|pay.now|place.order|checkout|complete.order"

        combined_text = html.lower()
        if checkout_link:
            combined_text += " " + checkout_link.lower()

        if re.search(technical_auth, combined_text):
            intent = "Auth / Validation 🛡️ (Verified by Code)"
        elif "add-payment-method" in (results.get("checkout_link") or ""):
            intent = "Auth / Elite Gate 💎 (Payment Method Page)"
        elif re.search(r"my-account|/account|/login", combined_text + (results.get("checkout_link") or "")):
            intent = "Auth / Account Gate 🛡️"
        elif re.search(auth_keywords, combined_text):
            intent = "Auth / Donation 🛡️"
        elif re.search(charge_keywords, combined_text):
            intent = "Charge 💰"

        results["intent"] = intent

        # ── PHASE 10: Finalize Account Link ─────────────────────
        c_link = results.get("checkout_link") or ""
        if "/my-account" in c_link or "/account" in c_link:
            results["account_page"] = c_link
        if "add-payment-method" in c_link:
            results["add_payment_link"] = c_link

        # ── PHASE 11: Lowest Price Discovery ────────────────────
        prices = re.findall(r"\$\s?(\d+\.\d{2})", html)
        if prices:
            try:
                numeric_prices = [float(p) for p in prices if float(p) > 0.1]
                if numeric_prices:
                    min_p = min(numeric_prices)
                    results["lowest_price"] = f"${min_p:.2f}"
                    price_str = f"{min_p:.2f}"
                    price_idx = html.find(price_str)
                    nearby_html = html[max(0, price_idx - 500) : price_idx + 500]
                    link_match = re.search(r'href=["\'](https?://[^"\']+|/[^"\']+)["\']', nearby_html)
                    if link_match:
                        p_link = link_match.group(1)
                        if p_link.startswith("/"):
                            p_link = domain_base.rstrip("/") + p_link
                        results["product_link"] = p_link
            except Exception:
                pass

        # ── PHASE 12: Calculate Risk Score ──────────────────────
        results["risk"] = self._calculate_risk(results)
        return results

    def _proxy_only_kwargs(self, proxy: str | None):
        """Like _client_kwargs but without overriding follow/timeouts elsewhere."""
        if not proxy:
            return {}
        proxy_url = f"http://{proxy}"
        try:
            httpx.AsyncClient(proxy=proxy_url, timeout=1.0)  # type: ignore[arg-type]
            return {"proxy": proxy_url}
        except TypeError:
            return {"proxies": {"http://": proxy_url, "https://": proxy_url}}

    def _extract_keys(self, html):
        """Extract API keys and sitekeys using predefined patterns."""
        extracted = []
        for name, pattern in self.KEY_PATTERNS.items():
            matches = re.findall(pattern, html, re.I)
            for m in matches:
                if isinstance(m, tuple):
                    val = next((item for item in m if item), None)
                    if val:
                        extracted.append(f"{name}: {val}")
                else:
                    extracted.append(f"{name}: {m}")

        # Sensitive patterns (redacted)
        for name, pattern in getattr(self, "SENSITIVE_KEY_PATTERNS", {}).items():
            matches = re.findall(pattern, html, re.I)
            for m in matches:
                if isinstance(m, tuple):
                    val = next((item for item in m if item), None)
                else:
                    val = m
                if not val:
                    continue
                extracted.append(f"{name}: {self._redact_secret(str(val))}")

        return extracted

    def _redact_secret(self, s: str) -> str:
        # Returns the full secret without masking
        return s or ""

    def _match_signatures(self, html, signature_dict):
        """Match HTML against a dictionary of named regex signature lists."""
        found = []
        for name, patterns in signature_dict.items():
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    found.append(name)
                    break
        return found

    def _match_signatures_allowed(self, html: str, signature_dict: dict, allowed: set[str]) -> list[str]:
        """Like _match_signatures but only for allowed gateway names."""
        found = []
        for name, patterns in signature_dict.items():
            if name not in allowed:
                continue
            for pattern in patterns:
                if re.search(pattern, html, re.I):
                    found.append(name)
                    break
        return found

    def _detect_security(self, html, headers, cookies_str):
        """Detect WAFs, CDNs, and bot-protection layers from headers + HTML."""
        security = []
        h = {k.lower(): v for k, v in headers.items()}

        cf_detected = False
        if any(x in h for x in ["cf-ray", "cf-cache-status", "cf-request-id"]):
            cf_detected = True

        if re.search(r"turnstile|challenges\.cloudflare\.com", html, re.I):
            security.append("Cloudflare Turnstile 🛡️")
        elif re.search(r"cf_chl_prog|cf_chl_rc_ni|cf-captcha-container", html + cookies_str, re.I):
            security.append("Cloudflare Managed Challenge 🛑")
        elif cf_detected:
            security.append("Cloudflare WAF/CDN ☁️")

        if re.search(r"/cdn-cgi/challenge", html, re.I):
            security.append("CF Under Attack 🔒")

        if any(x in h for x in ["x-akamai-transformed", "akamai-grn", "x-true-cache-key"]):
            security.append("Akamai 🛡️")
        if re.search(r"ak_bmsc|_abck|akamai-bot-manager", html + cookies_str, re.I):
            security.append("Akamai Bot Manager 🛡️")

        if re.search(r"visid_incap|incap_ses|_incap_", cookies_str, re.I) or "x-iinfo" in h:
            security.append("Imperva/Incapsula 🛡️")

        if re.search(r"datadome|dd\.js|dd\.co/dd", html + cookies_str, re.I):
            security.append("DataDome 🛡️")
        if re.search(r"_px|perimeterx|human\.com/sensor|px-client", html + cookies_str, re.I):
            security.append("PerimeterX/HUMAN 🛡️")

        if re.search(r"cleantalk|ct_checkjs|apic\.cleantalk", html + cookies_str, re.I):
            security.append("CleanTalk 🛡️")
        if re.search(r"shield-security|icwp-wpsf|wp-security", html + cookies_str, re.I):
            security.append("Shield Security 🛡️")

        return list(set(security))

    async def _discover_checkout(self, domain_base, homepage_html, proxy=None, headers=None):
        """
        Auto-discover checkout/payment pages.
        Now uses CMS-aware intelligence to prioritize the most likely paths.
        """
        cms_list = self._match_signatures(homepage_html, self.CMS_SIGNATURES)
        priority_paths = []

        if any("WooCommerce" in c for c in cms_list):
            priority_paths.extend(["/checkout/", "/cart/", "/my-account/"])
        if any("Shopify" in c for c in cms_list):
            priority_paths.extend(["/checkout", "/cart"])
        if any("Magento" in c for c in cms_list):
            priority_paths.extend(["/checkout/onepage/", "/checkout/"])

        priority_paths.extend(["/my-account/add-payment-method/", "/donate/", "/pay/"])

        internal_links = re.findall(r'href=["\']([^"\']+)["\']', homepage_html)
        checkout_keywords = r"checkout|cart|basket|donate|pay|billing|order|purchase|my-account|account|payment-method|subscribe|membership"
        candidate_urls = []

        for path in priority_paths:
            candidate_urls.append(domain_base.rstrip("/") + path)

        for link in internal_links:
            if re.search(checkout_keywords, link, re.I):
                if link.startswith("http"):
                    candidate_urls.append(link)
                elif link.startswith("/"):
                    candidate_urls.append(domain_base.rstrip("/") + link)

        for path in self.CHECKOUT_PATHS:
            candidate_urls.append(domain_base.rstrip("/") + path)

        # ── Deeper crawl: fetch a few internal "shop/product/category" pages
        # Many sites don't link checkout directly on the homepage.
        deep_seeds = []
        for link in internal_links:
            if not re.search(r"shop|product|collections|category|catalog|store|search", link, re.I):
                continue
            if link.startswith("http"):
                deep_seeds.append(link)
            elif link.startswith("/"):
                deep_seeds.append(domain_base.rstrip("/") + link)
            if len(deep_seeds) >= 3:
                break

        seen = set()
        unique_urls = []
        for u in candidate_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        unique_urls.sort(key=lambda x: 0 if re.search(r"account|payment-method", x, re.I) else 1)

        import random

        if not headers:
            headers = {"User-Agent": random.choice(self.user_agents)}

        async with httpx.AsyncClient(
            headers=headers,
            follow_redirects=True,
            timeout=8.0,
            verify=False,
            **self._proxy_only_kwargs(proxy),
        ) as client:
            # Add candidates from robots.txt + sitemap.xml
            try:
                seo_urls = await self._discover_from_robots_and_sitemaps(client, domain_base, checkout_keywords)
                unique_urls.extend(seo_urls)
            except Exception:
                pass

            # Expand candidates using a few deeper seed pages (best effort)
            for seed in deep_seeds:
                try:
                    seed_resp = await client.get(seed)
                    if seed_resp.status_code != 200:
                        continue
                    seed_html = seed_resp.text
                    seed_links = re.findall(r'href=["\']([^"\']+)["\']', seed_html)
                    for link in seed_links:
                        if not re.search(checkout_keywords, link, re.I):
                            continue
                        if link.startswith("http"):
                            unique_urls.append(link)
                        elif link.startswith("/"):
                            unique_urls.append(domain_base.rstrip("/") + link)
                except Exception:
                    continue

            # Deduplicate again after deep expansion
            seen2 = set()
            expanded = []
            for u in unique_urls:
                if u not in seen2:
                    seen2.add(u)
                    expanded.append(u)
            unique_urls = expanded

            # Probe more candidates; many stores hide checkout deeper.
            for test_url in unique_urls[:80]:
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200:
                        page_html = resp.text
                        # Validate: checkout/auth/payment pages vary widely.
                        # Use a broader set of indicators + allow strong URL hints.
                        url_hint = bool(re.search(r"checkout|cart|basket|payment|billing|order|my-account|account|add-payment-method", test_url, re.I))
                        content_hint = bool(
                            re.search(
                                r"payment_method|place\.?order|proceed.*checkout|checkout|cart|add to cart|"
                                r"billing|shipping|card number|credit card|cvv|expiry|"
                                r"add payment method|saved methods|payment methods",
                                page_html,
                                re.I,
                            )
                        )

                        if url_hint or content_hint:
                            extra_gw = self._match_signatures(page_html, self.GATEWAY_SIGNATURES)
                            extra_cap = self._match_signatures(page_html, self.CAPTCHA_SIGNATURES)
                            return test_url, extra_gw, extra_cap
                except Exception:
                    continue

        return None, [], []

    def _calculate_risk(self, results):
        """Calculate a security risk/difficulty score."""
        points = 0
        sec = results.get("security", "")
        cap = results.get("captcha", "")

        if "Cloudflare" in sec:
            points += 1
        if "Under Attack" in sec:
            points += 3
        if "Akamai" in sec:
            points += 2
        if "Bot Manager" in sec:
            points += 3
        if "Imperva" in sec or "Incapsula" in sec:
            points += 2
        if "DataDome" in sec:
            points += 3
        if "PerimeterX" in sec or "HUMAN" in sec:
            points += 4
        if "Kasada" in sec:
            points += 4
        if "Shape" in sec:
            points += 4

        if "reCAPTCHA v2" in cap:
            points += 2
        if "reCAPTCHA v3" in cap:
            points += 1
        if "Invisible" in cap:
            points += 2
        if "hCaptcha" in cap:
            points += 2
        if "GeeTest" in cap:
            points += 3
        if "FunCaptcha" in cap:
            points += 4
        if "DataDome" in cap:
            points += 5
        if "Turnstile" in cap:
            points += 2
        if "Altcha" in cap or "Friendly" in cap:
            points += 1

        if points == 0:
            return "Low 🟢"
        if points <= 2:
            return "Medium 🟡"
        if points <= 4:
            return "High 🟠"
        if points <= 7:
            return "Extreme 🔴"
        return "☠️ Critical / Impossible ☠️"


async def main():
    import sys

    sys.stdout.reconfigure(encoding="utf-8")

    analyzer = SiteAnalyzer()
    test_urls = [
        "https://globalgarden.co",
    ]
    for url in test_urls:
        print(f"\n{'=' * 50}")
        print(f"Scanning: {url}")
        print("=" * 50)
        res = await analyzer.analyze_site(url)
        for k, v in res.items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    asyncio.run(main())

