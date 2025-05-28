include "common.yara"

rule teemo : tracker
{
    meta:
        description = "Teemo"
        author      = "Abhi"
        url         = "https://www.teemo.co"

    strings:
        $code_signature    = /com\.databerries\.|com\.geolocstation\./
        $network_signature = /databerries\.com/
        $code_signature2   = /com\/databerries\/|com\/geolocstation\//

    condition:
        is_elf and any of them
}

rule fidzup : tracker
{
    meta:
        description = "FidZup"
        author      = "Abhi"
        url         = "https://www.fidzup.com"

    strings:
        $code_signature    = /com\.fidzup\./
        $network_signature = /fidzup/
        $code_signature2   = /com\/fidzup\//

    condition:
        is_elf and any of them
}

rule audience_studio_krux : tracker
{
    meta:
        description = "Audience Studio (Krux)"
        author      = "Abhi"
        url         = "https://www.salesforce.com/products/marketing-cloud/data-management/?mc=DMP"

    strings:
        $code_signature    = /com\.krux\.androidsdk/
        $network_signature = /krxd\.net/
        $code_signature2   = /com\/krux\/androidsdk/

    condition:
        is_elf and any of them
}

rule ad_screen : tracker
{
    meta:
        description = "Ad4Screen"
        author      = "Abhi"
        url         = "http://www.ad4screen.com"

    strings:
        $code_signature    = /com\.ad4screen\.sdk/
        $network_signature = /a4\.tl|accengage\.com|ad4push\.com|ad4screen\.com/
        $code_signature2   = /com\/ad4screen\/sdk/

    condition:
        is_elf and any of them
}

rule google_doubleclick : tracker
{
    meta:
        description = "G. DoubleClick"
        author      = "Abhi"
        url         = "https://www.doubleclickbygoogle.com/"

    strings:

        $network_signature = /2mdn\.net|dmtry\.com|doubleclick\.com|doubleclick\.net|mng-ads\.com/

    condition:
        is_elf and any of them
}

rule weborama : tracker
{
    meta:
        description = "Weborama"
        author      = "Abhi"
        url         = "https://www.weborama.com"

    strings:
        $code_signature    = /com\.weborama\./
        $network_signature = /weborama\.fr|weborama\.net/
        $code_signature2   = /com\/weborama\//

    condition:
        is_elf and any of them
}

rule smart : tracker
{
    meta:
        description = "Smart"
        author      = "Abhi"
        url         = "http://smartadserver.com/"

    strings:
        $code_signature    = /com\.smartadserver\./
        $network_signature = /adsrvr\.org|akamai\.smartadserver\.com|cdn1\.smartadserver\.com|diff2\.smartadserver\.com|diff3\.smartadserver\.com|diff\.smartadserver\.com|eqx\.smartadserver\.com|gallery\.smartadserver\.com|im2\.smartadserver\.com|insight\.adsrvr\.org|itx5-publicidad\.smartadserver\.com|itx5\.smartadserver\.com|js\.adsrvr\.org|match\.adsrvr\.org|preview\.smartadserver\.com|rtb-csync\.smartadserver\.com|saspreview\.com|smartadserver\.com|smartadserver\.ru|tmk\.smartadserver\.com|usw\-lax\.adsrvr\.org/
        $code_signature2   = /com\/smartadserver\//

    condition:
        is_elf and any of them
}

rule jw_player : tracker
{
    meta:
        description = "JW Player"
        author      = "Abhi"
        url         = "https://jwplayer.com"

    strings:
        $code_signature    = /com\.longtailvideo\.jwplayer\./
        $network_signature = /g\.jwpsrv\.com|jwpltx\.com|p\.jwpcdn\.com/
        $code_signature2   = /com\/longtailvideo\/jwplayer\//

    condition:
        is_elf and any of them
}

rule loggly : tracker
{
    meta:
        description = "Loggly"
        author      = "Abhi"
        url         = "http://loggly.com/"

    strings:
        $code_signature    = /com\.github\.tony19\.timber\.loggly|com\.github\.tony19\.loggly|com\.visiware\.sync2ad\.logger\.loggly\./
        $network_signature = /loggly\.com/
        $code_signature2   = /com\/github\/tony19\/timber\/loggly|com\/github\/tony19\/loggly|com\/visiware\/sync2ad\/logger\/loggly\//

    condition:
        is_elf and any of them
}

rule outbrain : tracker
{
    meta:
        description = "OutBrain"
        author      = "Abhi"
        url         = "http://www.outbrain.com/"

    strings:
        $code_signature    = /com\.outbrain\./
        $network_signature = /outbrain\.com/
        $code_signature2   = /com\/outbrain\//

    condition:
        is_elf and any of them
}

rule appsflyer : tracker
{
    meta:
        description = "AppsFlyer"
        author      = "Abhi"
        url         = "http://AppsFlyer.com"

    strings:
        $code_signature    = /com\.appsflyer\./
        $network_signature = /appsflyer\.com/
        $code_signature2   = /com\/appsflyer\//

    condition:
        is_elf and any of them
}

rule ligatus : tracker
{
    meta:
        description = "Ligatus"
        author      = "Abhi"
        url         = "http://ligatus.com"

    strings:
        $code_signature    = /\.LigatusManager|\.LigatusViewClient|com\.ligatus\.android\.adframework/
        $network_signature = /ligatus\.com/
        $code_signature2   = /\/LigatusManager|\/LigatusViewClient|com\/ligatus\/android\/adframework/

    condition:
        is_elf and any of them
}

rule widespace : tracker
{
    meta:
        description = "Widespace"
        author      = "Abhi"
        url         = "http://widespace.com"

    strings:
        $code_signature    = /com\.widespace\./
        $network_signature = /widespace\.com/
        $code_signature2   = /com\/widespace\//

    condition:
        is_elf and any of them
}

rule appnexus : tracker
{
    meta:
        description = "AppNexus"
        author      = "Abhi"
        url         = "https://www.appnexus.com/"

    strings:
        $code_signature    = /com\.appnexus\.opensdk\./
        $network_signature = /247realmedia\.com|adnxs\.com|appnexus\.com|appnexus\.net/
        $code_signature2   = /com\/appnexus\/opensdk\//

    condition:
        is_elf and any of them
}

rule localytics : tracker
{
    meta:
        description = "Localytics"
        author      = "Abhi"
        url         = "http://localytics.com"

    strings:
        $code_signature    = /com\.localytics\.android\.|com\.localytics\.androidx|com\.localytics\.react\./
        $network_signature = /analytics\.localytics\.com|manifest\.localytics\.com|profile\.localytics\.com|sdk-assets\.localytics\.com/
        $code_signature2   = /com\/localytics\/android\/|com\/localytics\/androidx|com\/localytics\/react\//

    condition:
        is_elf and any of them
}

rule braze_formerly_appboy : tracker
{
    meta:
        description = "Braze (formerly Appboy)"
        author      = "Abhi"
        url         = "https://www.braze.com"

    strings:
        $code_signature    = /com\.appboy/
        $network_signature = /appboy\.com/
        $code_signature2   = /com\/appboy/

    condition:
        is_elf and any of them
}

rule mparticle : tracker
{
    meta:
        description = "mParticle"
        author      = "Abhi"
        url         = "http://mparticle.com"

    strings:
        $code_signature    = /com\.mparticle/
        $network_signature = /mparticle\.com/
        $code_signature2   = /com\/mparticle/

    condition:
        is_elf and any of them
}

rule s_m : tracker
{
    meta:
        description = "S4M"
        author      = "Abhi"
        url         = "http://www.s4m.io/"

    strings:
        $code_signature    = /com\.sam4mobile\.|\.S4MAnalytic/
        $network_signature = /s4m\.io|sam4m\.com/
        $code_signature2   = /com\/sam4mobile\/|\/S4MAnalytic/

    condition:
        is_elf and any of them
}

rule sizmek : tracker
{
    meta:
        description = "Sizmek"
        author      = "Abhi"
        url         = "https://www.sizmek.com"

    strings:
        $code_signature    = /\.sizmek\./
        $network_signature = /serving-sys\.com/
        $code_signature2   = /\/sizmek\//

    condition:
        is_elf and any of them
}

rule batch : tracker
{
    meta:
        description = "Batch"
        author      = "Abhi"
        url         = "https://batch.com"

    strings:
        $code_signature    = /com\.batch\.android\./
        $network_signature = /batch\.com/
        $code_signature2   = /com\/batch\/android\//

    condition:
        is_elf and any of them
}

rule sync_ad : tracker
{
    meta:
        description = "Sync2Ad"
        author      = "Abhi"
        url         = "https://www.sync2ad.com/"

    strings:
        $code_signature    = /com\.visiware\.sync2ad\.dmp\./
        $network_signature = /sync2ad\.com/
        $code_signature2   = /com\/visiware\/sync2ad\/dmp\//

    condition:
        is_elf and any of them
}

rule flurry : tracker
{
    meta:
        description = "Flurry"
        author      = "Abhi"
        url         = "http://www.flurry.com"

    strings:
        $code_signature    = /com\.flurry\./
        $network_signature = /flurry\.com/
        $code_signature2   = /com\/flurry\//

    condition:
        is_elf and any of them
}

rule hockeyapp : tracker
{
    meta:
        description = "HockeyApp"
        author      = "Abhi"
        url         = "http://hockeyapp.net"

    strings:
        $code_signature    = /net\.hockeyapp\./
        $network_signature = /hockeyapp\.net/
        $code_signature2   = /net\/hockeyapp\//

    condition:
        is_elf and any of them
}

rule google_crashlytics : tracker
{
    meta:
        description = "G. CrashLytics"
        author      = "Abhi"
        url         = "http://crashlytics.com"

    strings:
        $code_signature    = /io\.fabric\.|com\.crashlytics\.|com\.google\.firebase\.crashlytics|com\.google\.firebase\.crash\.|io\.invertase\.firebase\.crashlytics\./
        $network_signature = /crashlytics\.com/
        $code_signature2   = /io\/fabric\/|com\/crashlytics\/|com\/google\/firebase\/crashlytics|com\/google\/firebase\/crash\/|io\/invertase\/firebase\/crashlytics\//

    condition:
        is_elf and any of them
}

rule leanplum : tracker
{
    meta:
        description = "LeanPlum"
        author      = "Abhi"
        url         = "https://www.leanplum.com/"

    strings:
        $code_signature    = /com\.leanplum\./
        $network_signature = /leanplum\.com/
        $code_signature2   = /com\/leanplum\//

    condition:
        is_elf and any of them
}

rule tinder_analytics : tracker
{
    meta:
        description = "Tinder Analytics"
        author      = "Abhi"
        url         = "http://tinder.com"

    strings:
        $code_signature    = /com\.tinder\.analytics|com\.tinder\.ads/
        $network_signature = /etl\.tindersparks\.com/
        $code_signature2   = /com\/tinder\/analytics|com\/tinder\/ads/

    condition:
        is_elf and any of them
}

rule schibsted : tracker
{
    meta:
        description = "Schibsted"
        author      = "Abhi"
        url         = "http://www.schibsted.com/en/ir/"

    strings:
        $code_signature    = /\.schibsted\./
        $network_signature = /schibsted\.com|schibsted\.io/
        $code_signature2   = /\/schibsted\//

    condition:
        is_elf and any of them
}

rule atinternet : tracker
{
    meta:
        description = "ATInternet"
        author      = "Abhi"
        url         = "https://www.atinternet.com/en/"

    strings:
        $code_signature    = /com\.atinternet\./
        $network_signature = /ati-host\.net/
        $code_signature2   = /com\/atinternet\//

    condition:
        is_elf and any of them
}

rule tealium : tracker
{
    meta:
        description = "Tealium"
        author      = "Abhi"
        url         = "https://tealium.com/"

    strings:
        $code_signature    = /\.tealium\./
        $network_signature = /tealiumiq\.com|tiqcdn\.com/
        $code_signature2   = /\/tealium\//

    condition:
        is_elf and any of them
}

rule nexage : tracker
{
    meta:
        description = "Nexage"
        author      = "Abhi"
        url         = "http://nexage.com/"

    strings:
        $code_signature    = /com\.nexage\.android\.|org\.nexage\./
        $network_signature = /nexage\.com/
        $code_signature2   = /com\/nexage\/android\/|org\/nexage\//

    condition:
        is_elf and any of them
}

rule ogury_presage : tracker
{
    meta:
        description = "Ogury Presage"
        author      = "Abhi"
        url         = "http://www.presage.io/"

    strings:
        $code_signature    = /io\.presage\./
        $network_signature = /presage\.io/
        $code_signature2   = /io\/presage\//

    condition:
        is_elf and any of them
}

rule twitter_mopub : tracker
{
    meta:
        description = "Twitter MoPub"
        author      = "Abhi"
        url         = "https://www.mopub.com/"

    strings:
        $code_signature    = /com\.mopub\./
        $network_signature = /mopub\.com/
        $code_signature2   = /com\/mopub\//

    condition:
        is_elf and any of them
}

rule add_apt_tr : tracker
{
    meta:
        description = "Add Apt Tr"
        author      = "Abhi"
        url         = "https://www.addapptr.com"

    strings:
        $code_signature    = /com\.intentsoftware\.addapptr\./
        $network_signature = /aatkit\.com/
        $code_signature2   = /com\/intentsoftware\/addapptr\//

    condition:
        is_elf and any of them
}

rule vectaury : tracker
{
    meta:
        description = "Vectaury"
        author      = "Abhi"
        url         = "http://vectaury.io/"

    strings:
        $code_signature    = /io\.vectaury\./
        $network_signature = /vectaury\.io/
        $code_signature2   = /io\/vectaury\//

    condition:
        is_elf and any of them
}

rule tune : tracker
{
    meta:
        description = "Tune"
        author      = "Abhi"
        url         = "https://www.tune.com"

    strings:
        $code_signature    = /com\.tune|com\.mobileapptracker/
        $network_signature = /mobileapptracking\.com/
        $code_signature2   = /com\/tune|com\/mobileapptracker/

    condition:
        is_elf and any of them
}

rule pushwoosh : tracker
{
    meta:
        description = "Pushwoosh"
        author      = "Abhi"
        url         = "https://www.pushwoosh.com/"

    strings:
        $code_signature    = /com\.pushwoosh/
        $network_signature = /pushwoosh\.com/
        $code_signature2   = /com\/pushwoosh/

    condition:
        is_elf and any of them
}

rule demdex : tracker
{
    meta:
        description = "Demdex"
        author      = "Abhi"
        url         = "https://www.adobe.com/data-analytics-cloud/audience-manager.html"

    strings:
        $code_signature    = /com\.adobe\.mobile\.Analytics|com\.adobe\.mobile\.Config\./
        $network_signature = /demdex\.net/
        $code_signature2   = /com\/adobe\/mobile\/Analytics|com\/adobe\/mobile\/Config\//

    condition:
        is_elf and any of them
}

rule adswizz : tracker
{
    meta:
        description = "AdsWizz"
        author      = "Abhi"
        url         = "http://www.adswizz.com/"

    strings:
        $code_signature    = /\.adswizz\./
        $network_signature = /adswizz\.com|cdn\.adswizz.com\.edgesuite\.net/
        $code_signature2   = /\/adswizz\//

    condition:
        is_elf and any of them
}

rule exacttarget : tracker
{
    meta:
        description = "ExactTarget"
        author      = "Abhi"
        url         = "http://help.exacttarget.com/en/technical_library/API_Overview/"

    strings:
        $code_signature    = /com\.exacttarget\./
        $network_signature = /\.exacttarget\./
        $code_signature2   = /com\/exacttarget\//

    condition:
        is_elf and any of them
}

rule omniture : tracker
{
    meta:
        description = "Omniture"
        author      = "Abhi"
        url         = "https://www.adobe.com/analytics/adobe-analytics-features.html"

    strings:
        $code_signature    = /com\.omniture\.|com\.adobe\.adms\.measurement\./
        $network_signature = /omniture\.com|omtrdc\.net/
        $code_signature2   = /com\/omniture\/|com\/adobe\/adms\/measurement\//

    condition:
        is_elf and any of them
}

rule openlocate : tracker
{
    meta:
        description = "OpenLocate"
        author      = "Abhi"
        url         = "https://www.safegraph.com/"

    strings:
        $code_signature    = /com\.safegraph\.|com\.openlocate/
        $network_signature = /api\.safegraph\.com/
        $code_signature2   = /com\/safegraph\/|com\/openlocate/

    condition:
        is_elf and any of them
}

rule tagcommander_commanders_act : tracker
{
    meta:
        description = "TagCommander (Commanders Act.)"
        author      = "Abhi"
        url         = "https://www.commandersact.com/"

    strings:
        $code_signature    = /com\.tagcommander\./
        $network_signature = /\.commander1\.com|\.tagcommander.com/
        $code_signature2   = /com\/tagcommander\//

    condition:
        is_elf and any of them
}

rule crowdtangle : tracker
{
    meta:
        description = "CrowdTangle"
        author      = "Abhi"
        url         = "https://www.crowdtangle.com/"

    strings:

        $network_signature = /api\.crowdtangle\.com/

    condition:
        is_elf and any of them
}

rule facebook_audience : tracker
{
    meta:
        description = "FB. Audience"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android/"

    strings:
        $code_signature    = /com\.facebook\.audiencenetwork/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/audiencenetwork/

    condition:
        is_elf and any of them
}

rule google_analytics : tracker
{
    meta:
        description = "G. Analytics"
        author      = "Abhi"
        url         = "http://www.google.com/analytics/"

    strings:
        $code_signature    = /com\.google\.android\.apps\.analytics\.|com\.google\.android\.gms\.analytics\.|com\.google\.analytics\./
        $network_signature = /google-analytics\.com/
        $code_signature2   = /com\/google\/android\/apps\/analytics\/|com\/google\/android\/gms\/analytics\/|com\/google\/analytics\//

    condition:
        is_elf and any of them
}

rule google_firebase_analytics : tracker
{
    meta:
        description = "G. Firebase Analytics"
        author      = "Abhi"
        url         = "https://firebase.google.com/"

    strings:
        $code_signature    = /com\.google\.firebase\.analytics\.FirebaseAnalytics|com\.google\.android\.gms\.measurement\.|com\.google\.firebase\.firebase_analytics/
        $network_signature = /firebase\.com|firebaselogging-pa\.googleapis\.com/
        $code_signature2   = /com\/google\/firebase\/analytics\/FirebaseAnalytics|com\/google\/android\/gms\/measurement\/|com\/google\/firebase\/firebase_analytics/

    condition:
        is_elf and any of them
}

rule eulerian : tracker
{
    meta:
        description = "Eulerian"
        author      = "Abhi"
        url         = "https://www.eulerian.com/en/"

    strings:
        $code_signature    = /com\.eulerian\.android\.sdk/
        $network_signature = /eulerian\.com/
        $code_signature2   = /com\/eulerian\/android\/sdk/

    condition:
        is_elf and any of them
}

rule adjust : tracker
{
    meta:
        description = "Adjust"
        author      = "Abhi"
        url         = "https://www.adjust.com/"

    strings:
        $code_signature    = /com\.adjust\.sdk\.|com\.adjust\.android\.sdk\./
        $network_signature = /adj\.st|adjust\.com|go\.link/
        $code_signature2   = /com\/adjust\/sdk\/|com\/adjust\/android\/sdk\//

    condition:
        is_elf and any of them
}

rule chartboost : tracker
{
    meta:
        description = "ChartBoost"
        author      = "Abhi"
        url         = "https://answers.chartboost.com/en-us/"

    strings:
        $code_signature    = /com\.chartboost\.sdk\./
        $network_signature = /\.chartboost\.com/
        $code_signature2   = /com\/chartboost\/sdk\//

    condition:
        is_elf and any of them
}

rule backelite : tracker
{
    meta:
        description = "Backelite"
        author      = "Abhi"
        url         = "https://www.backelite.com/"

    strings:
        $code_signature    = /com\.backelite\.android\.|com\.backelite\.bkdroid\./
        $network_signature = /backelite\.com/
        $code_signature2   = /com\/backelite\/android\/|com\/backelite\/bkdroid\//

    condition:
        is_elf and any of them
}

rule areametrics : tracker
{
    meta:
        description = "Areametrics"
        author      = "Abhi"
        url         = "https://areametrics.com/"

    strings:
        $code_signature    = /com\.areametrics\.areametricssdk|com\.areametrics\.nosdkandroid/
        $network_signature = /areametrics\.com/
        $code_signature2   = /com\/areametrics\/areametricssdk|com\/areametrics\/nosdkandroid/

    condition:
        is_elf and any of them
}

rule comscore : tracker
{
    meta:
        description = "ComScore"
        author      = "Abhi"
        url         = "https://comscore.com/"

    strings:
        $code_signature    = /com\.comscore\./
        $network_signature = /comscore\.com/
        $code_signature2   = /com\/comscore\//

    condition:
        is_elf and any of them
}

rule cuebiq : tracker
{
    meta:
        description = "Cuebiq"
        author      = "Abhi"
        url         = "http://www.cuebiq.com/"

    strings:
        $code_signature    = /com\.cuebiq\.cuebiqsdk\.model\.Collector|com\.cuebiq\.cuebiqsdk\.receiver\.CoverageReceiver/
        $network_signature = /cuebiq\.com/
        $code_signature2   = /com\/cuebiq\/cuebiqsdk\/model\/Collector|com\/cuebiq\/cuebiqsdk\/receiver\/CoverageReceiver/

    condition:
        is_elf and any of them
}

rule helpshift : tracker
{
    meta:
        description = "HelpShift"
        author      = "Abhi"
        url         = "https://www.helpshift.com"

    strings:
        $code_signature    = /com\.helpshift/
        $network_signature = /helpshift\.com/
        $code_signature2   = /com\/helpshift/

    condition:
        is_elf and any of them
}

rule kontakt : tracker
{
    meta:
        description = "Kontakt"
        author      = "Abhi"
        url         = "https://kontakt.io/"

    strings:
        $code_signature    = /com\.kontakt\.sdk\.android\./
        $network_signature = /kontakt\.io/
        $code_signature2   = /com\/kontakt\/sdk\/android\//

    condition:
        is_elf and any of them
}

rule locuslabs : tracker
{
    meta:
        description = "Locuslabs"
        author      = "Abhi"
        url         = "http://locuslabs.com"

    strings:
        $code_signature    = /com\.locuslabs\.sdk/
        $network_signature = /locuslabs\.com/
        $code_signature2   = /com\/locuslabs\/sdk/

    condition:
        is_elf and any of them
}

rule moat : tracker
{
    meta:
        description = "Moat"
        author      = "Abhi"
        url         = "https://moat.com/analytics"

    strings:
        $code_signature    = /com\.moat\.analytics\.mobile\./
        $network_signature = /apx\.moatads\.com|geo\.moatads\.com|js\.moatads\.com|mb\.moatads\.com|moat\.com|pixel\.moatads\.com|px\.moatads\.com|sejs\.moatads\.com|yt\.moatads\.com|yts\.moatads\.com|z\.moatads\.com/
        $code_signature2   = /com\/moat\/analytics\/mobile\//

    condition:
        is_elf and any of them
}

rule segment : tracker
{
    meta:
        description = "Segment"
        author      = "Abhi"
        url         = "https://segment.com/"

    strings:
        $code_signature    = /com\.segment\.analytics\./
        $network_signature = /api\.segment\.io|segment\.com/
        $code_signature2   = /com\/segment\/analytics\//

    condition:
        is_elf and any of them
}

rule mobile_engagement : tracker
{
    meta:
        description = "Mobile Engagement"
        author      = "Abhi"
        url         = "https://docs.microsoft.com/en-us/azure/mobile-engagement/mobile-engagement-android-sdk-overview"

    strings:
        $code_signature    = /com\.ubikod\.capptain\.|com\.microsoft\.azure\.engagement\./
        $network_signature = /login\.microsoftonline\.com|management\.azure\.com/
        $code_signature2   = /com\/ubikod\/capptain\/|com\/microsoft\/azure\/engagement\//

    condition:
        is_elf and any of them
}

rule colocator : tracker
{
    meta:
        description = "Colocator"
        author      = "Abhi"
        url         = "https://developers.colocator.net"

    strings:
        $code_signature    = /net\.crowdconnected\.androidcolocator/
        $network_signature = /colocator\.net/
        $code_signature2   = /net\/crowdconnected\/androidcolocator/

    condition:
        is_elf and any of them
}

rule facebook_ads : tracker
{
    meta:
        description = "FB. Ads"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.ads/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/ads/

    condition:
        is_elf and any of them
}

rule facebook_analytics : tracker
{
    meta:
        description = "FB. Analytics"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.appevents|com\.facebook\.marketing\.|com\.facebook\.CampaignTrackingReceiver/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/appevents|com\/facebook\/marketing\/|com\/facebook\/CampaignTrackingReceiver/

    condition:
        is_elf and any of them
}

rule facebook_login : tracker
{
    meta:
        description = "FB. Login"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.login/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/login/

    condition:
        is_elf and any of them
}

rule facebook_notifications : tracker
{
    meta:
        description = "FB. Notifs"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.notifications/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/notifications/

    condition:
        is_elf and any of them
}

rule facebook_places : tracker
{
    meta:
        description = "FB. Places"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.places/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/places/

    condition:
        is_elf and any of them
}

rule facebook_share : tracker
{
    meta:
        description = "FB. Share"
        author      = "Abhi"
        url         = "https://developers.facebook.com/docs/android"

    strings:
        $code_signature    = /com\.facebook\.share/
        $network_signature = /\.facebook\.com/
        $code_signature2   = /com\/facebook\/share/

    condition:
        is_elf and any of them
}

rule google_ads : tracker
{
    meta:
        description = "G. Ads"
        author      = "Abhi"
        url         = "https://developers.google.com/admob/android"

    strings:

        $network_signature = /\.google\.com/
            $admob_sig     = /com\.google\.android\.gms\.ads\.identifier/
            $admob_sig2    = /com\/google\/android\/gms\/ads\/identifier/

    condition:
        is_elf and any of them
}

rule applovin_max_and_sparklabs : tracker
{
    meta:
        description = "AppLovin (MAX and SparkLabs)"
        author      = "Abhi"
        url         = "https://www.applovin.com/"

    strings:
        $code_signature    = /com\.applovin/
        $network_signature = /applovin\.com|applvn\.com/
        $code_signature2   = /com\/applovin/

    condition:
        is_elf and any of them
}

rule glispa_connect_formerly_avocarrot : tracker
{
    meta:
        description = "Glispa Connect (Formerly Avocarrot)"
        author      = "Abhi"
        url         = "https://www.glispa.com"

    strings:
        $code_signature    = /com\.avocarrot\.sdk/
        $network_signature = /\.avocarrot\.com|ads\.glispa\.com|exp\.glispa\.com|rtb\.platform\.glispa\.com|templates\.glispaconnect\.com|trk\.glispa\.com/
        $code_signature2   = /com\/avocarrot\/sdk/

    condition:
        is_elf and any of them
}

rule nativex : tracker
{
    meta:
        description = "NativeX"
        author      = "Abhi"
        url         = "http://www.nativex.com/"

    strings:
        $code_signature    = /com\.nativex/
        $network_signature = /nativex\.com/
        $code_signature2   = /com\/nativex/

    condition:
        is_elf and any of them
}

rule baidu_maps : tracker
{
    meta:
        description = "Baidu Maps"
        author      = "Abhi"
        url         = "https://map.baidu.com"

    strings:
        $code_signature    = /com\.baidu\.BaiduMap/
        $network_signature = /map\.baidu\.com/
        $code_signature2   = /com\/baidu\/BaiduMap/

    condition:
        is_elf and any of them
}

rule wechat_location : tracker
{
    meta:
        description = "WeChat Location"
        author      = "Abhi"
        url         = "https://wechat.com"

    strings:
        $code_signature    = /com\.tencent\.map\.geolocation|com\.tencent\.mm\.plugin\.location\.|com\.tencent\.mm\.plugin\.location_soso\.|com\.tencent\.mm\.plugin\.location_google/
        $network_signature = /map\.qq\.com/
        $code_signature2   = /com\/tencent\/map\/geolocation|com\/tencent\/mm\/plugin\/location\/|com\/tencent\/mm\/plugin\/location_soso\/|com\/tencent\/mm\/plugin\/location_google/

    condition:
        is_elf and any of them
}

rule hypertrack : tracker
{
    meta:
        description = "HyperTrack"
        author      = "Abhi"
        url         = "http://hypertrack.com"

    strings:
        $code_signature    = /com\.hypertrack|com\.hypertracklive\.|io\.hypertrack/
        $network_signature = /api\.hypertrack\.com|hypertrack\.amazonaws\.com|trck\.at/
        $code_signature2   = /com\/hypertrack|com\/hypertracklive\/|io\/hypertrack/

    condition:
        is_elf and any of them
}

rule uber_analytics : tracker
{
    meta:
        description = "Uber Analytics"
        author      = "Abhi"
        url         = "https://uber.com"

    strings:
        $code_signature    = /com\.ubercab\.analytics\.|com\.ubercab\.library\.metrics\.analytics\.|com\.ubercab\.client\.core\.analytics\./
        $network_signature = /events\.uber\.com/
        $code_signature2   = /com\/ubercab\/analytics\/|com\/ubercab\/library\/metrics\/analytics\/|com\/ubercab\/client\/core\/analytics\//

    condition:
        is_elf and any of them
}

rule lisnr : tracker
{
    meta:
        description = "Lisnr"
        author      = "Abhi"
        url         = "http://lisnr.com"

    strings:
        $code_signature    = /com\.lisnr\./
        $network_signature = /lisnr\.com/
        $code_signature2   = /com\/lisnr\//

    condition:
        is_elf and any of them
}

rule silverpush : tracker
{
    meta:
        description = "SilverPush"
        author      = "Abhi"
        url         = "http://silverpush.co"

    strings:
        $code_signature    = /com\.silverpush\./
        $network_signature = /54\.243\.73\.253:8080\\SilverPush\\|silverpush\.co|silverpush\.com/
        $code_signature2   = /com\/silverpush\//

    condition:
        is_elf and any of them
}

rule shopkick : tracker
{
    meta:
        description = "Shopkick"
        author      = "Abhi"
        url         = "https://shopkick.com"

    strings:
        $code_signature    = /com\.shopkick\.sdk\.api\.|com\.shopkick\.fetchers\./
        $network_signature = /sdk\.shopkick\.com|shopkick\.com|shopkick\.de/
        $code_signature2   = /com\/shopkick\/sdk\/api\/|com\/shopkick\/fetchers\//

    condition:
        is_elf and any of them
}

rule alphonso : tracker
{
    meta:
        description = "Alphonso"
        author      = "Abhi"
        url         = "http://alphonso.tv"

    strings:
        $code_signature    = /tv\.alphonso\.service/
        $network_signature = /api\.alphonso\.tv|prov\.alphonso\.tv/
        $code_signature2   = /tv\/alphonso\/service/

    condition:
        is_elf and any of them
}

rule smaato : tracker
{
    meta:
        description = "Smaato"
        author      = "Abhi"
        url         = "https://smaato.com"

    strings:
        $code_signature    = /com\.smaato\./
        $network_signature = /smaato\.net|soma\.smaato\.net/
        $code_signature2   = /com\/smaato\//

    condition:
        is_elf and any of them
}

rule scandit : tracker
{
    meta:
        description = "Scandit"
        author      = "Abhi"
        url         = "https://scandit.com"

    strings:
        $code_signature    = /com\.scandit\./
        $network_signature = /scandit\.com/
        $code_signature2   = /com\/scandit\//

    condition:
        is_elf and any of them
}

rule inrix : tracker
{
    meta:
        description = "Inrix"
        author      = "Abhi"
        url         = "http://inrix.com/"

    strings:
        $code_signature    = /com\.inrix\.sdk/
        $network_signature = /inrix\.com|inrix\.io/
        $code_signature2   = /com\/inrix\/sdk/

    condition:
        is_elf and any of them
}

rule signal_ : tracker
{
    meta:
        description = "Signal360"
        author      = "Abhi"
        url         = "http://www.signal360.com"

    strings:
        $code_signature    = /com\.signal360\.sdk\.core\.|com\.sonicnotify\.sdk\.core\.|com\.rnsignal360/
        $network_signature = /signal360\.com|sonicnotify\.com/
        $code_signature2   = /com\/signal360\/sdk\/core\/|com\/sonicnotify\/sdk\/core\/|com\/rnsignal360/

    condition:
        is_elf and any of them
}

rule telequid : tracker
{
    meta:
        description = "TeleQuid"
        author      = "Abhi"
        url         = "http://www.telequid.com/"

    strings:
        $code_signature    = /com\.telequid\./
        $network_signature = /mars\.telequid\.com/
        $code_signature2   = /com\/telequid\//

    condition:
        is_elf and any of them
}

rule retency : tracker
{
    meta:
        description = "Retency"
        author      = "Abhi"
        url         = "http://retency.com"

    strings:
        $code_signature    = /com\.retency\.sdk\.android/
        $code_signature2   = /com\/retency\/sdk\/android/

    condition:
        is_elf and any of them
}

rule madvertise : tracker
{
    meta:
        description = "MAdvertise"
        author      = "Abhi"
        url         = "http://madvertise.com"

    strings:
        $code_signature    = /com\.mngads\.sdk|com\.mngads\.views|com\.mngads\./
        $network_signature = /dispatcher\.mng\-ads\.com|mobile\.mng\-ads\.com/
        $code_signature2   = /com\/mngads\/sdk|com\/mngads\/views|com\/mngads\//

    condition:
        is_elf and any of them
}

rule adcolony : tracker
{
    meta:
        description = "AdColony"
        author      = "Abhi"
        url         = "http://adcolony.com/"

    strings:
        $code_signature    = /com\.adcolony\.|com\.jirbo\.adcolony\./
        $network_signature = /adc3-launch\.adcolony\.com|adcolony\.com|ads30\.adcolony\.com|androidads20\.adcolony\.com|androidads21\.adcolony\.com|androidads23\.adcolony\.com|events3alt\.adcolony\.com|wd\.adcolony\.com/
        $code_signature2   = /com\/adcolony\/|com\/jirbo\/adcolony\//

    condition:
        is_elf and any of them
}

rule accountkit : tracker
{
    meta:
        description = "AccountKit"
        author      = "Abhi"
        url         = "https://www.accountkit.com/"

    strings:
        $code_signature    = /com\.facebook\.accountkit/
        $network_signature = /graph\.accountkit\.com/
        $code_signature2   = /com\/facebook\/accountkit/

    condition:
        is_elf and any of them
}

rule amazon_advertisement : tracker
{
    meta:
        description = "Amazon Advertisement"
        author      = "Abhi"
        url         = "https://developer.amazon.com/public/apis/earn/mobile-ads/docs/quick-start"

    strings:
        $code_signature    = /com\.amazon\.device\.ads/
        $code_signature2   = /com\/amazon\/device\/ads/

    condition:
        is_elf and any of them
}

rule amazon_mobile_associates : tracker
{
    meta:
        description = "Amazon Mobile Associates"
        author      = "Abhi"
        url         = "https://developer.amazon.com/mobile-associates"

    strings:
        $code_signature    = /com\.amazon\.device\.associates/
        $code_signature2   = /com\/amazon\/device\/associates/

    condition:
        is_elf and any of them
}

rule radius_networks : tracker
{
    meta:
        description = "Radius Networks"
        author      = "Abhi"
        url         = "https://www.radiusnetworks.com/"

    strings:
        $code_signature    = /com\.radiusnetworks/
        $network_signature = /proximitykit\.radiusnetworks\.com/
        $code_signature2   = /com\/radiusnetworks/

    condition:
        is_elf and any of them
}

rule amazon_analytics_amazon_insights : tracker
{
    meta:
        description = "Amazon Analytics (Amazon insights)"
        author      = "Abhi"
        url         = "https://developer.amazon.com/docs/apps-and-games/sdk-downloads.html"

    strings:
        $code_signature    = /com\.amazon\.insights|com\.amazonaws\.mobileconnectors\.pinpoint\.analytics\.|com\.amazonaws\.mobileconnectors\.amazonmobileanalytics/
        $network_signature = /mobileanalytics\.us-east-1\.amazonaws\.com/
        $code_signature2   = /com\/amazon\/insights|com\/amazonaws\/mobileconnectors\/pinpoint\/analytics\/|com\/amazonaws\/mobileconnectors\/amazonmobileanalytics/

    condition:
        is_elf and any of them
}

rule baidu_appx : tracker
{
    meta:
        description = "Baidu APPX"
        author      = "Abhi"
        url         = "https://app.baidu.com/"

    strings:
        $code_signature    = /com\.baidu\.appx/
        $code_signature2   = /com\/baidu\/appx/

    condition:
        is_elf and any of them
}

rule baidu_location : tracker
{
    meta:
        description = "Baidu Location"
        author      = "Abhi"
        url         = "https://developer.baidu.com/"

    strings:
        $code_signature    = /com\.baidu\.location/
        $code_signature2   = /com\/baidu\/location/

    condition:
        is_elf and any of them
}

rule baidu_mobile_ads : tracker
{
    meta:
        description = "Baidu Mobile Ads"
        author      = "Abhi"
        url         = "https://developer.baidu.com/"

    strings:
        $code_signature    = /com\.baidu\.mobads/
        $code_signature2   = /com\/baidu\/mobads/

    condition:
        is_elf and any of them
}

rule baidu_mobile_stat : tracker
{
    meta:
        description = "Baidu Mobile Stat"
        author      = "Abhi"
        url         = "https://developer.baidu.com/"

    strings:
        $code_signature    = /com\.baidu\.mobstat/
        $code_signature2   = /com\/baidu\/mobstat/

    condition:
        is_elf and any of them
}

rule estimote : tracker
{
    meta:
        description = "Estimote"
        author      = "Abhi"
        url         = "https://estimote.com/"

    strings:
        $code_signature    = /com\.estimote\./
        $network_signature = /.*\.estimote\.com/
        $code_signature2   = /com\/estimote\//

    condition:
        is_elf and any of them
}

rule baidu_navigation : tracker
{
    meta:
        description = "Baidu Navigation"
        author      = "Abhi"
        url         = "http://lbsyun.baidu.com/index.php?title=android-navsdk"

    strings:
        $code_signature    = /com\.baidu\.navi/
        $code_signature2   = /com\/baidu\/navi/

    condition:
        is_elf and any of them
}

rule fyber : tracker
{
    meta:
        description = "Fyber"
        author      = "Abhi"
        url         = "https://www.fyber.com/"

    strings:
        $code_signature    = /com\.fyber\./
        $network_signature = /adproxy\.fyber\.com|appengage-video\.fyber\.com|banner\.fyber\.com|engine\.fyber\.com|interstitial\.fyber\.com|mbe-cdn\.fyber\.com|offer\.fyber\.com|service\.fyber\.com|tracker\.fyber\.com|video-interstitial-assets-cdn\.fyber\.com|video\.fyber\.com/
        $code_signature2   = /com\/fyber\//

    condition:
        is_elf and any of them
}

rule google_tag_manager : tracker
{
    meta:
        description = "G. Tag Manager"
        author      = "Abhi"
        url         = "https://www.google.com/analytics/tag-manager/"

    strings:
        $code_signature    = /com\.google\.tagmanager|com\.google\.android\.gms\.tagmanager/
        $network_signature = /www\.googletagmanager\.com|www\.googletagservices\.com|www-googletagmanager\.l\.google\.com/
        $code_signature2   = /com\/google\/tagmanager|com\/google\/android\/gms\/tagmanager/

    condition:
        is_elf and any of them
}

rule inmobi : tracker
{
    meta:
        description = "Inmobi"
        author      = "Abhi"
        url         = "http://inmobi.com"

    strings:
        $code_signature    = /com\.inmobi|in\.inmobi\./
        $network_signature = /c\.w\.inmobi\.com|china\.inmobi\.com|config-ltvp\.inmobi\.com|config\.inmobi\.com|et\.w\.inmobi\.com|i\.l\.inmobicdn\.net|i\.w\.inmobi\.com|inmobi\.cn|inmobi\.com|inmobi\.info|inmobi\.net|inmobi\.us|inmobicdn\.com|inmobicdn\.net|inmobisdk\-a\.akamaihd\.net|japan\.inmobi\.com|r\.w\.inmobi\.com|sdkm\.w\.inmobi\.com|sdktm\.w\.inmobi\.com|w\.inmobi\.com/
        $code_signature2   = /com\/inmobi|in\/inmobi\//

    condition:
        is_elf and any of them
}

rule millennial_media : tracker
{
    meta:
        description = "Millennial Media"
        author      = "Abhi"
        url         = "https://www.millennialmedia.com/"

    strings:
        $code_signature    = /com\.millennialmedia\./
        $network_signature = /adtech\.de|contextual\.media\.net|media\.net|millennialmedia\.com/
        $code_signature2   = /com\/millennialmedia\//

    condition:
        is_elf and any of them
}

rule snowplow : tracker
{
    meta:
        description = "Snowplow"
        author      = "Abhi"
        url         = "https://snowplowanalytics.com/"

    strings:
        $code_signature    = /com\.snowplowanalytics\./
        $code_signature2   = /com\/snowplowanalytics\//

    condition:
        is_elf and any of them
}

rule fyber_sponsorpay : tracker
{
    meta:
        description = "Fyber SponsorPay"
        author      = "Abhi"
        url         = "http://www.sponsorpay.com"

    strings:
        $code_signature    = /com\.sponsorpay/
        $network_signature = /appengage-video\.sponsorpay\.com|cdn1\.sponsorpay\.com|cdn2\.sponsorpay\.com|cdn3\.sponsorpay\.com|cdn4\.sponsorpay\.com|engine\.sponsorpay\.com/
        $code_signature2   = /com\/sponsorpay/

    condition:
        is_elf and any of them
}

rule supersonic_ads : tracker
{
    meta:
        description = "Supersonic Ads"
        author      = "Abhi"
        url         = "https://www.supersonic.com/"

    strings:
        $code_signature    = /com\.supersonic\.adapters\.supersonicads|com\.supersonicads\.sdk/
        $network_signature = /click-haproxy\.supersonicads\.com|cx\.ssacdn\.com|init\.supersonicads\.com|logs\.supersonic\.com|outcome\.supersonicads\.com|ow-gateway\.supersonicads\.com|pixel-tracking\.sonic-us\.supersonicads\.com|rv-gateway\.supersonicads\.com|static\.ssacdn\.com|supersonic\.com|supersonicads-a\.akamaihd\.net|tag\-mediation.supersonic.com|ua\.supersonicads\.com|v\.ssacdn\.com|www\.supersonicads\.com/
        $code_signature2   = /com\/supersonic\/adapters\/supersonicads|com\/supersonicads\/sdk/

    condition:
        is_elf and any of them
}

rule carnival : tracker
{
    meta:
        description = "Carnival"
        author      = "Abhi"
        url         = "http://carnival.io/"

    strings:
        $code_signature    = /com\.carnival\.sdk|com\.carnivalmobile/
        $network_signature = /devices\.carnivalmobile\.com/
        $code_signature2   = /com\/carnival\/sdk|com\/carnivalmobile/

    condition:
        is_elf and any of them
}

rule tencent_map_lbs : tracker
{
    meta:
        description = "Tencent Map LBS"
        author      = "Abhi"
        url         = "https://lbs.qq.com/"

    strings:
        $code_signature    = /com\.tencent\.lbs/
        $code_signature2   = /com\/tencent\/lbs/

    condition:
        is_elf and any of them
}

rule tencent_mobwin : tracker
{
    meta:
        description = "Tencent MobWin"
        author      = "Abhi"
        url         = "https://www.tencent.com/en-us/"

    strings:
        $code_signature    = /com\.tencent\.mobwin/
        $code_signature2   = /com\/tencent\/mobwin/

    condition:
        is_elf and any of them
}

rule tencent_mta : tracker
{
    meta:
        description = "Tencent MTA"
        author      = "Abhi"
        url         = "https://mta.qq.com/"

    strings:
        $code_signature    = /com\.tencent\.mta/
        $code_signature2   = /com\/tencent\/mta/

    condition:
        is_elf and any of them
}

rule apptentive : tracker
{
    meta:
        description = "Apptentive"
        author      = "Abhi"
        url         = "https://www.apptentive.com/"

    strings:
        $code_signature    = /com\.apptentive\./
        $network_signature = /api\.apptentive\.com/
        $code_signature2   = /com\/apptentive\//

    condition:
        is_elf and any of them
}

rule tencent_stats : tracker
{
    meta:
        description = "Tencent Stats"
        author      = "Abhi"
        url         = "http://stat.qq.com/"

    strings:
        $code_signature    = /com\.tencent\.stat|com\.tencent\.wxop\.stat/
        $code_signature2   = /com\/tencent\/stat|com\/tencent\/wxop\/stat/

    condition:
        is_elf and any of them
}

rule tencent_weiyun : tracker
{
    meta:
        description = "Tencent Weiyun"
        author      = "Abhi"
        url         = "https://www.weiyun.com"

    strings:
        $code_signature    = /com\.tencent\.weiyun/
        $code_signature2   = /com\/tencent\/weiyun/

    condition:
        is_elf and any of them
}

rule mixpanel : tracker
{
    meta:
        description = "MixPanel"
        author      = "Abhi"
        url         = "https://mixpanel.com/"

    strings:
        $code_signature    = /com\.mixpanel\./
        $network_signature = /api\.mixpanel\.com|decide\.mixpanel\.com|mixpanel\.com|switchboard\.mixpanel\.com/
        $code_signature2   = /com\/mixpanel\//

    condition:
        is_elf and any of them
}

rule umeng_analytics : tracker
{
    meta:
        description = "Umeng Analytics"
        author      = "Abhi"
        url         = "https://www.umeng.com/analytics"

    strings:
        $code_signature    = /com\.umeng\.analytics/
        $network_signature = /alog\.umeng\.com|alogs\.umeng\.com|ar\.umeng\.com|oc\.umeng\.com|umeng\.com|uop\.umeng\.com/
        $code_signature2   = /com\/umeng\/analytics/

    condition:
        is_elf and any of them
}

rule umeng_feedback : tracker
{
    meta:
        description = "Umeng Feedback"
        author      = "Abhi"
        url         = "http://dev.umeng.com/feedback"

    strings:
        $code_signature    = /com\.umeng\.fb/
        $network_signature = /alog\.umeng\.com|alogs\.umeng\.com|ar\.umeng\.com|oc\.umeng\.com|umeng\.com|uop\.umeng\.com/
        $code_signature2   = /com\/umeng\/fb/

    condition:
        is_elf and any of them
}

rule unity_d_ads : tracker
{
    meta:
        description = "Unity3d Ads"
        author      = "Abhi"
        url         = "https://unity3d.com/"

    strings:
        $code_signature    = /com\.unity3d\.services|com\.unity3d\.ads/
        $network_signature = /adserver\.unityads\.unity3d\.com|analytics\.social\.unity\.com|api\.uca\.cloud\.unity3d\.com|auction\.unityads\.unity3d\.com|cdn-highwinds\.unityads\.unity3d\.com|cdn\.unityads\.unity3d\.com|config\.uca\.cloud\.unity3d\.com|config\.unityads\.unity3d\.com|stats\.unity3d\.com|webview\.unityads\.unity3d\.com/
        $code_signature2   = /com\/unity3d\/services|com\/unity3d\/ads/

    condition:
        is_elf and any of them
}

rule countly : tracker
{
    meta:
        description = "Countly"
        author      = "Abhi"
        url         = "https://count.ly/"

    strings:
        $code_signature    = /ly\.count\.android\./
        $code_signature2   = /ly\/count\/android\//

    condition:
        is_elf and any of them
}

rule urbanairship : tracker
{
    meta:
        description = "Urbanairship"
        author      = "Abhi"
        url         = "https://www.urbanairship.com/"

    strings:
        $code_signature    = /com\.urbanairship/
        $network_signature = /device-api\.urbanairship\.com|urbanairship\.com|device-api\.asnapieu\.com/
        $code_signature2   = /com\/urbanairship/

    condition:
        is_elf and any of them
}

rule yandex_ad : tracker
{
    meta:
        description = "Yandex Ad"
        author      = "Abhi"
        url         = "https://www.yandex.com/"

    strings:
        $code_signature    = /com\.yandex\.mobile\.ads/
        $network_signature = /analytics\.mobile\.yandex\.net|appmetrica\.yandex\.com|banners-slb\.mobile\.yandex\.net|banners\.mobile\.yandex\.net|mc\.yandex\.ru|report\.appmetrica\.yandex\.net|startup\.mobile\.yandex\.net/
        $code_signature2   = /com\/yandex\/mobile\/ads/

    condition:
        is_elf and any of them
}

rule amplitude : tracker
{
    meta:
        description = "Amplitude"
        author      = "Abhi"
        url         = "http://www.amplitude.com"

    strings:
        $code_signature    = /com\.amplitude\./
        $network_signature = /amplitude\.com|api\.amplitude\.com/
        $code_signature2   = /com\/amplitude\//

    condition:
        is_elf and any of them
}

rule appsee : tracker
{
    meta:
        description = "AppSee"
        author      = "Abhi"
        url         = "https://www.appsee.com/"

    strings:
        $code_signature    = /com\.appsee\./
        $network_signature = /api\.appsee\.com/
        $code_signature2   = /com\/appsee\//

    condition:
        is_elf and any of them
}

rule kochava : tracker
{
    meta:
        description = "Kochava"
        author      = "Abhi"
        url         = "https://www.kochava.com/"

    strings:
        $code_signature    = /com\.kochava\.base\.|com\.kochava\.android\.tracker\.|\.kochavaccpa\./
        $network_signature = /control\.kochava\.com|kvinit\-prod\.api\.kochava\.com/
        $code_signature2   = /com\/kochava\/base\/|com\/kochava\/android\/tracker\/|\/kochavaccpa\//

    condition:
        is_elf and any of them
}

rule webtrends : tracker
{
    meta:
        description = "Webtrends"
        author      = "Abhi"
        url         = "https://www.webtrends.com/"

    strings:
        $code_signature    = /com\.webtrends\.mobile\.analytics\.|com\.webtrends\.mobile\.android/
        $network_signature = /dc\.webtrends\.com|webtrends\.com/
        $code_signature2   = /com\/webtrends\/mobile\/analytics\/|com\/webtrends\/mobile\/android/

    condition:
        is_elf and any of them
}

rule new_relic : tracker
{
    meta:
        description = "New Relic"
        author      = "Abhi"
        url         = "http://www.newrelic.com"

    strings:
        $code_signature    = /com\.newrelic\.agent\.|com\.newrelic\.mobile\./
        $network_signature = /js-agent\.newrelic\.com|mobile-collector\.newrelic\.com|newrelic\.com|nr-data\.net/
        $code_signature2   = /com\/newrelic\/agent\/|com\/newrelic\/mobile\//

    condition:
        is_elf and any of them
}

rule appanalytics : tracker
{
    meta:
        description = "AppAnalytics"
        author      = "Abhi"
        url         = "http://appanalytics.io/"

    strings:
        $code_signature    = /io\.appanalytics\.sdk/
        $code_signature2   = /io\/appanalytics\/sdk/

    condition:
        is_elf and any of them
}

rule applause : tracker
{
    meta:
        description = "Applause"
        author      = "Abhi"
        url         = "http://www.applause.com"

    strings:
        $code_signature    = /com\.applause\.android\./
        $code_signature2   = /com\/applause\/android\//

    condition:
        is_elf and any of them
}

rule quantcast : tracker
{
    meta:
        description = "Quantcast"
        author      = "Abhi"
        url         = "http://www.quantcast.com"

    strings:
        $code_signature    = /com\.quantcast\.measurement\.service\./
        $network_signature = /quantcast\.com|quantcast\.net/
        $code_signature2   = /com\/quantcast\/measurement\/service\//

    condition:
        is_elf and any of them
}

rule apptimize : tracker
{
    meta:
        description = "Apptimize"
        author      = "Abhi"
        url         = "http://www.apptimize.com"

    strings:
        $code_signature    = /com\.apptimize\./
        $network_signature = /brahe\.apptimize\.com|md-a-c\.apptimize\.com|md-a-s\.apptimize\.com/
        $code_signature2   = /com\/apptimize\//

    condition:
        is_elf and any of them
}

rule appbrain : tracker
{
    meta:
        description = "AppBrain"
        author      = "Abhi"
        url         = "https://www.appbrain.com/info/help/sdk/index.html"

    strings:
        $code_signature    = /com\.appbrain\./
        $network_signature = /sdk\.appbrain\.com/
        $code_signature2   = /com\/appbrain\//

    condition:
        is_elf and any of them
}

rule dynatrace : tracker
{
    meta:
        description = "Dynatrace"
        author      = "Abhi"
        url         = "https://www.dynatrace.com"

    strings:
        $code_signature    = /com\.dynatrace\.android\.app|com\.dynatrace\.agent|com\.dynatrace\.tools/
        $network_signature = /\.dynatrace\.com/
        $code_signature2   = /com\/dynatrace\/android\/app|com\/dynatrace\/agent|com\/dynatrace\/tools/

    condition:
        is_elf and any of them
}

rule matomo_piwik : tracker
{
    meta:
        description = "Matomo (Piwik)"
        author      = "Abhi"
        url         = "https://matomo.org/mobile"

    strings:
        $code_signature    = /org\.piwik|org\.piwik\.mobile|org\.matomo/
        $network_signature = /matomo\.org/
        $code_signature2   = /org\/piwik|org\/piwik\/mobile|org\/matomo/

    condition:
        is_elf and any of them
}

rule singlespot : tracker
{
    meta:
        description = "Singlespot"
        author      = "Abhi"
        url         = "https://www.singlespot.com/"

    strings:
        $code_signature    = /com\.sptproximitykit\./
        $network_signature = /singlespot\.com/
        $code_signature2   = /com\/sptproximitykit\//

    condition:
        is_elf and any of them
}

rule sensoro : tracker
{
    meta:
        description = "Sensoro"
        author      = "Abhi"
        url         = "https://www.sensoro.com/"

    strings:
        $code_signature    = /com\.sensoro\.beacon\.kit\.|com\.sensoro\.cloud/
        $code_signature2   = /com\/sensoro\/beacon\/kit\/|com\/sensoro\/cloud/

    condition:
        is_elf and any of them
}

rule sense_ : tracker
{
    meta:
        description = "Sense360"
        author      = "Abhi"
        url         = "https://sense360.com/"

    strings:
        $code_signature    = /com\.sense360\.android\./
        $network_signature = /android-quinoa-config-prod\.sense360eng\.com|incoming-data-sense360\.s3\.amazonaws\.com|quinoa-personal-identify-prod\.sense360eng\.com/
        $code_signature2   = /com\/sense360\/android\//

    condition:
        is_elf and any of them
}

rule rubicon_project : tracker
{
    meta:
        description = "Rubicon Project"
        author      = "Abhi"
        url         = "https://rubiconproject.com"

    strings:
        $code_signature    = /com\.rfm\.sdk/
        $network_signature = /ads\.rubiconproject\.com|fastlane\.rubiconproject\.com|optimized-by\.rubiconproject\.com|pixel\.rubiconproject\.com|stats\.aws\.rubiconproject\.com|tap2-cdn\.rubiconproject\.com|video-ads\.rubiconproject\.com/
        $code_signature2   = /com\/rfm\/sdk/

    condition:
        is_elf and any of them
}

rule ironsource : tracker
{
    meta:
        description = "ironSource"
        author      = "Abhi"
        url         = "https://www.ironsrc.com"

    strings:
        $code_signature    = /com\.ironsource\./
        $code_signature2   = /com\/ironsource\//

    condition:
        is_elf and any of them
}

rule heyzap_bought_by_fyber : tracker
{
    meta:
        description = "Heyzap (bought by Fyber)"
        author      = "Abhi"
        url         = "https://www.heyzap.com"

    strings:
        $code_signature    = /com\.heyzap\.sdk\.ads\.|com\.heyzap\.mediation\./
        $network_signature = /ads\.heyzap\.com|fyc\.heyzap\.com|img-cloudflare-2\.haizap\.com|img-cloudflare\.haizap\.com|med\.heyzap\.com|x\.heyzap\.com/
        $code_signature2   = /com\/heyzap\/sdk\/ads\/|com\/heyzap\/mediation\//

    condition:
        is_elf and any of them
}

rule sap_cdc_gigya : tracker
{
    meta:
        description = "SAP CDC (Gigya)"
        author      = "Abhi"
        url         = "https://www.sap.com/products/crm/customer-data-management.html"

    strings:
        $code_signature    = /com\.gigya\./
        $network_signature = /cdn1\.gigya\.com|cdn2\.gigya\.com|cdn3\.gigya\.com|cdn\.gigya\.com|cdns\.us1\.gigya\.com|david\.gigya-cs\.com/
        $code_signature2   = /com\/gigya\//

    condition:
        is_elf and any of them
}

rule foresee : tracker
{
    meta:
        description = "Foresee"
        author      = "Abhi"
        url         = "https://www.foresee.com"

    strings:
        $code_signature    = /com\.foresee\.sdk\.ForeSee/
        $network_signature = /4seeresults\.com|analytics\.foresee\.com|foresee\.com|foreseeresults\.com|i\.4see\.mobi|rec\.replay\.answerscloud\.com/
        $code_signature2   = /com\/foresee\/sdk\/ForeSee/

    condition:
        is_elf and any of them
}

rule fiksu : tracker
{
    meta:
        description = "Fiksu"
        author      = "Abhi"
        url         = "https://fiksu.com"

    strings:
        $code_signature    = /com\.fiksu\.asotracking/
        $network_signature = /a\.fiksu\.com|sdk\.fiksu\.com/
        $code_signature2   = /com\/fiksu\/asotracking/

    condition:
        is_elf and any of them
}

rule ensighten : tracker
{
    meta:
        description = "Ensighten"
        author      = "Abhi"
        url         = "https://www.ensighten.com"

    strings:
        $code_signature    = /com\.ensighten\./
        $network_signature = /nexus\.ensighten\.com/
        $code_signature2   = /com\/ensighten\//

    condition:
        is_elf and any of them
}

rule dynamic_yield : tracker
{
    meta:
        description = "Dynamic Yield"
        author      = "Abhi"
        url         = "https://www.dynamicyield.com"

    strings:
        $code_signature    = /com\.dynamicyield\./
        $network_signature = /adm\.dynamicyield\.com|api\.dynamicyield\.com|cdn\.dynamicyield\.com|px\.dynamicyield\.com|st\.dynamicyield\.com/
        $code_signature2   = /com\/dynamicyield\//

    condition:
        is_elf and any of them
}

rule bluekai_acquired_by_oracle : tracker
{
    meta:
        description = "BlueKai (acquired by Oracle)"
        author      = "Abhi"
        url         = "http://bluekai.com/registry/"

    strings:
        $code_signature    = /com\.bluekai\.sdk\./
        $network_signature = /stags\.bluekai\.com|tags\.bluekai\.com/
        $code_signature2   = /com\/bluekai\/sdk\//

    condition:
        is_elf and any of them
}

rule blueconic : tracker
{
    meta:
        description = "BlueConic"
        author      = "Abhi"
        url         = "https://www.blueconic.com"

    strings:
        $code_signature    = /com\.blueconic/
        $code_signature2   = /com\/blueconic/

    condition:
        is_elf and any of them
}

rule apteligent_by_vmware_formerly_crittercism : tracker
{
    meta:
        description = "Apteligent by VMWare (formerly Crittercism)"
        author      = "Abhi"
        url         = "http://www.apteligent.com"

    strings:
        $code_signature    = /com\.crittercism\.app\.Crittercism/
        $network_signature = /api\.crittercism\.com|appload\.ingest\.crittercism\.com|txn\.ingest\.crittercism\.com/
        $code_signature2   = /com\/crittercism\/app\/Crittercism/

    condition:
        is_elf and any of them
}

rule adfit_daum : tracker
{
    meta:
        description = "AdFit (Daum)"
        author      = "Abhi"
        url         = "https://www.daum.net"

    strings:
        $code_signature    = /com\.kakao\.adfit\./
        $network_signature = /analytics\.ad\.daum\.net|statistics\.videofarm\.daum\.net/
        $code_signature2   = /com\/kakao\/adfit\//

    condition:
        is_elf and any of them
}

rule adform : tracker
{
    meta:
        description = "Adform"
        author      = "Abhi"
        url         = "https://site.adform.com"

    strings:
        $code_signature    = /com\.adform\.sdk\./
        $network_signature = /adform\.com|adformdsp\.net|adx\.adform\.net|files\.adform\.net|track\.adform\.net/
        $code_signature2   = /com\/adform\/sdk\//

    condition:
        is_elf and any of them
}

rule adfurikun : tracker
{
    meta:
        description = "Adfurikun"
        author      = "Abhi"
        url         = "https://adfurikun.jp/adfurikun/"

    strings:
        $code_signature    = /jp\.tjkapp\.adfurikunsdk\.|com\.glossomads\.sdk\./
        $network_signature = /adfurikun\.jp|ginf\.adfurikun\.jp/
        $code_signature2   = /jp\/tjkapp\/adfurikunsdk\/|com\/glossomads\/sdk\//

    condition:
        is_elf and any of them
}

rule mobvista : tracker
{
    meta:
        description = "Mobvista"
        author      = "Abhi"
        url         = "https://www.mobvista.com/"

    strings:
        $code_signature    = /com\.mobvista\./
        $network_signature = /mobvista\.com/
        $code_signature2   = /com\/mobvista\//

    condition:
        is_elf and any of them
}

rule placed : tracker
{
    meta:
        description = "Placed"
        author      = "Abhi"
        url         = "http://placed.com/"

    strings:
        $code_signature    = /com\.placed\.client/
        $code_signature2   = /com\/placed\/client/

    condition:
        is_elf and any of them
}

rule adot : tracker
{
    meta:
        description = "Adot"
        author      = "Abhi"
        url         = "https://we-are-adot.com/"

    strings:
        $code_signature    = /com\.adotmob/
        $network_signature = /sdk\.adotmob\.com|sync\.adotmob\.com|tracker\.adotmob\.com/
        $code_signature2   = /com\/adotmob/

    condition:
        is_elf and any of them
}

rule appodeal : tracker
{
    meta:
        description = "Appodeal"
        author      = "Abhi"
        url         = "https://www.appodeal.com"

    strings:
        $code_signature    = /com\.appodeal\.ads\.|com\.appodealx\./
        $network_signature = /appodeal\.com|appodealx\.com/
        $code_signature2   = /com\/appodeal\/ads\/|com\/appodealx\//

    condition:
        is_elf and any of them
}

rule appmonet : tracker
{
    meta:
        description = "AppMonet"
        author      = "Abhi"
        url         = "http://appmonet.com"

    strings:
        $code_signature    = /com\.monet\./
        $code_signature2   = /com\/monet\//

    condition:
        is_elf and any of them
}

rule soomla : tracker
{
    meta:
        description = "Soomla"
        author      = "Abhi"
        url         = "https://soomla.com/"

    strings:
        $code_signature    = /com\.soomla\./
        $network_signature = /soom\.la/
        $code_signature2   = /com\/soomla\//

    condition:
        is_elf and any of them
}

rule adincube : tracker
{
    meta:
        description = "Adincube"
        author      = "Abhi"
        url         = "https://www.adincube.com/"

    strings:
        $code_signature    = /com\.adincube\.sdk\./
        $network_signature = /sdk\.adincube\.com/
        $code_signature2   = /com\/adincube\/sdk\//

    condition:
        is_elf and any of them
}

rule persona_ly : tracker
{
    meta:
        description = "Persona.ly"
        author      = "Abhi"
        url         = "http://persona.ly/"

    strings:
        $code_signature    = /ly\.persona\.sdk/
        $network_signature = /dev-api\.persona\.ly|dev\.dsp\.persona\.ly|dev\.persona\.ly|dsp\.persona\.ly|persona\.ly|rtb\.persona\.ly|sdk\.persona\.ly/
        $code_signature2   = /ly\/persona\/sdk/

    condition:
        is_elf and any of them
}

rule branch : tracker
{
    meta:
        description = "Branch"
        author      = "Abhi"
        url         = "https://branch.io/"

    strings:
        $code_signature    = /io\.branch\./
        $network_signature = /api\.branch\.io/
        $code_signature2   = /io\/branch\//

    condition:
        is_elf and any of them
}

rule cheetah_ads : tracker
{
    meta:
        description = "Cheetah Ads"
        author      = "Abhi"
        url         = "https://www.cmcm.com/"

    strings:
        $code_signature    = /com\.cmcm\./
        $network_signature = /cmcm\.com/
        $code_signature2   = /com\/cmcm\//

    condition:
        is_elf and any of them
}

rule vungle : tracker
{
    meta:
        description = "Vungle"
        author      = "Abhi"
        url         = "https://vungle.com"

    strings:
        $code_signature    = /com\.vungle\.publisher\.|com\.vungle\.warren\./
        $network_signature = /ads\.api\.vungle\.com|akamai\.vungle\-cdn\.vungle\.com|api\.vungle\.akadns\.net|api\.vungle\.com|bd\.vungle\.com|billboard\.vungle\.com|cdn\-lb\.vungle\.com|ci\.vungle\.com|data\.vungle\.com|ingest\.vungle\.com|jaeger\.vungle\.com|ltv\-data\-api\.kube\-prod\.vungle\.com|monitoring\.vungle\.com|ssl\.vungle\.com|v\.vungle\.com/
        $code_signature2   = /com\/vungle\/publisher\/|com\/vungle\/warren\//

    condition:
        is_elf and any of them
}

rule criteo : tracker
{
    meta:
        description = "Criteo"
        author      = "Abhi"
        url         = "https://www.criteo.com/"

    strings:
        $code_signature    = /com\.criteo\./
        $network_signature = /criteo\.com/
        $code_signature2   = /com\/criteo\//

    condition:
        is_elf and any of them
}

rule mapbox : tracker
{
    meta:
        description = "Mapbox"
        author      = "Abhi"
        url         = "https://www.mapbox.com/"

    strings:
        $code_signature    = /com\.mapbox\.mapboxsdk\.module\.telemetry|com\.mapbox\.mapboxsdk\.maps\.TelemetryDefinition|com\.mapbox\.android\.telemetry\./
        $network_signature = /a\.tiles\.mapbox\.com|api\.tiles\.mapbox\.com/
        $code_signature2   = /com\/mapbox\/mapboxsdk\/module\/telemetry|com\/mapbox\/mapboxsdk\/maps\/TelemetryDefinition|com\/mapbox\/android\/telemetry\//

    condition:
        is_elf and any of them
}

rule optimizely : tracker
{
    meta:
        description = "Optimizely"
        author      = "Abhi"
        url         = "https://www.optimizely.com/"

    strings:
        $code_signature    = /com\.optimizely\./
        $network_signature = /optimizely\.com|optimizelyapis\.com/
        $code_signature2   = /com\/optimizely\//

    condition:
        is_elf and any of them
}

rule taboola : tracker
{
    meta:
        description = "Taboola"
        author      = "Abhi"
        url         = "https://www.taboola.com/"

    strings:
        $code_signature    = /com\.taboola\./
        $network_signature = /taboola\.com/
        $code_signature2   = /com\/taboola\//

    condition:
        is_elf and any of them
}

rule clevertap : tracker
{
    meta:
        description = "CleverTap"
        author      = "Abhi"
        url         = "https://clevertap.com/"

    strings:
        $code_signature    = /com\.clevertap\./
        $network_signature = /wzrkt\.com/
        $code_signature2   = /com\/clevertap\//

    condition:
        is_elf and any of them
}

rule mytracker : tracker
{
    meta:
        description = "myTracker"
        author      = "Abhi"
        url         = "https://tracker.my.com/"

    strings:
        $code_signature    = /com\.my\.tracker\./
        $network_signature = /tracker-api\.my\.com/
        $code_signature2   = /com\/my\/tracker\//

    condition:
        is_elf and any of them
}

rule cloudmobi : tracker
{
    meta:
        description = "Cloudmobi"
        author      = "Abhi"
        url         = "http://www.cloudmobi.net/"

    strings:
        $code_signature    = /com\.cloudtech\./
        $network_signature = /api\.cloudmobi\.net|cloudmobi\.net|logger\.cloudmobi\.net|vast\.cloudmobi\.net/
        $code_signature2   = /com\/cloudtech\//

    condition:
        is_elf and any of them
}

rule adlib : tracker
{
    meta:
        description = "ADLIB"
        author      = "Abhi"
        url         = "https://adlibr.com"

    strings:
        $code_signature    = /com\.mocoplex\.adlib\./
        $network_signature = /adlibr\.com/
        $code_signature2   = /com\/mocoplex\/adlib\//

    condition:
        is_elf and any of them
}

rule brightcove : tracker
{
    meta:
        description = "Brightcove"
        author      = "Abhi"
        url         = "https://www.brightcove.com"

    strings:
        $code_signature    = /com\.brightcove/
        $network_signature = /metrics\.brightcove\.com/
        $code_signature2   = /com\/brightcove/

    condition:
        is_elf and any of them
}

rule dov_e : tracker
{
    meta:
        description = "DOV-E"
        author      = "Abhi"
        url         = "https://www.dov-e.com/"

    strings:
        $code_signature    = /com\.dv\.DVSDK/
        $network_signature = /\.dov-e\.com/
        $code_signature2   = /com\/dv\/DVSDK/

    condition:
        is_elf and any of them
}

rule inmarket : tracker
{
    meta:
        description = "InMarket"
        author      = "Abhi"
        url         = "https://inmarket.com/"

    strings:
        $code_signature    = /com\.inmarket/
        $network_signature = /m2m-api\.inmarket\.com/
        $code_signature2   = /com\/inmarket/

    condition:
        is_elf and any of them
}

rule pilgrim_by_foursquare : tracker
{
    meta:
        description = "Pilgrim by Foursquare"
        author      = "Abhi"
        url         = "https://enterprise.foursquare.com/products/pilgrim"

    strings:
        $code_signature    = /com\.foursquare\.pilgrim|com\.foursquare\.pilgrimsdk\.android/
        $network_signature = /sdk\.foursquare\.com/
        $code_signature2   = /com\/foursquare\/pilgrim|com\/foursquare\/pilgrimsdk\/android/

    condition:
        is_elf and any of them
}

rule otherlevels : tracker
{
    meta:
        description = "OtherLevels"
        author      = "Abhi"
        url         = "https://www.otherlevels.com/"

    strings:
        $code_signature    = /com\.otherlevels\./
        $network_signature = /api\.otherlevels\.com|geodata\.otherlevels\.com|mdn\.otherlevels\.com|rich\.otherlevels\.com|tags\.otherlevels\.com|ws\.otherlevels\.com/
        $code_signature2   = /com\/otherlevels\//

    condition:
        is_elf and any of them
}

rule pubnative : tracker
{
    meta:
        description = "PubNative"
        author      = "Abhi"
        url         = "https://pubnative.net/"

    strings:
        $code_signature    = /net\.pubnative/
        $network_signature = /pubnative\.net/
        $code_signature2   = /net\/pubnative/

    condition:
        is_elf and any of them
}

rule appnext : tracker
{
    meta:
        description = "Appnext"
        author      = "Abhi"
        url         = "https://www.appnext.com/"

    strings:
        $code_signature    = /com\.appnext\.sdk/
        $network_signature = /appnext.com/
        $code_signature2   = /com\/appnext\/sdk/

    condition:
        is_elf and any of them
}

rule mobfox : tracker
{
    meta:
        description = "MobFox"
        author      = "Abhi"
        url         = "https://www.mobfox.com/"

    strings:
        $code_signature    = /com\.mobfox\.|com\.adsdk\.sdk\./
        $code_signature2   = /com\/mobfox\/|com\/adsdk\/sdk\//

    condition:
        is_elf and any of them
}

rule shallwead : tracker
{
    meta:
        description = "ShallWeAD"
        author      = "Abhi"
        url         = "http://www.shallwead.com"

    strings:
        $code_signature    = /com\.jm\.co\.shallwead\.sdk\.|com\.co\.shallwead\.sdk\./
        $code_signature2   = /com\/jm\/co\/shallwead\/sdk\/|com\/co\/shallwead\/sdk\//

    condition:
        is_elf and any of them
}

rule deltadna : tracker
{
    meta:
        description = "deltaDNA"
        author      = "Abhi"
        url         = "https://deltadna.com/"

    strings:
        $code_signature    = /com\.deltadna/
        $network_signature = /deltadna\.net/
        $code_signature2   = /com\/deltadna/

    condition:
        is_elf and any of them
}

rule display : tracker
{
    meta:
        description = "Display"
        author      = "Abhi"
        url         = "https://www.display.io/en/"

    strings:
        $code_signature    = /io\.display\./
        $network_signature = /display.io/
        $code_signature2   = /io\/display\//

    condition:
        is_elf and any of them
}

rule hyprmx : tracker
{
    meta:
        description = "HyprMX"
        author      = "Abhi"
        url         = "https://www.hyprmx.com"

    strings:
        $code_signature    = /com\.hyprmx\.android\.sdk\./
        $network_signature = /hyprmx\.com/
        $code_signature2   = /com\/hyprmx\/android\/sdk\//

    condition:
        is_elf and any of them
}

rule bugly : tracker
{
    meta:
        description = "Bugly"
        author      = "Abhi"
        url         = "https://bugly.qq.com/v2/"

    strings:
        $code_signature    = /com\.tencent\.bugly\./
        $network_signature = /bugly\.qq\.com/
        $code_signature2   = /com\/tencent\/bugly\//

    condition:
        is_elf and any of them
}

rule duapps : tracker
{
    meta:
        description = "Duapps"
        author      = "Abhi"
        url         = "http://ad.duapps.com/"

    strings:
        $code_signature    = /com\.duapps\./
        $network_signature = /duapps\.com/
        $code_signature2   = /com\/duapps\//

    condition:
        is_elf and any of them
}

rule swrve : tracker
{
    meta:
        description = "Swrve"
        author      = "Abhi"
        url         = "https://www.swrve.com/"

    strings:
        $code_signature    = /com\.swrve\.sdk/
        $network_signature = /api\.swrve\.com|content\.swrve\.com/
        $code_signature2   = /com\/swrve\/sdk/

    condition:
        is_elf and any of them
}

rule onesignal : tracker
{
    meta:
        description = "OneSignal"
        author      = "Abhi"
        url         = "https://onesignal.com/"

    strings:
        $code_signature    = /com\.onesignal\./
        $network_signature = /onesignal\.com/
        $code_signature2   = /com\/onesignal\//

    condition:
        is_elf and any of them
}

rule appdynamics : tracker
{
    meta:
        description = "Appdynamics"
        author      = "Abhi"
        url         = "https://www.appdynamics.com/"

    strings:
        $code_signature    = /com\.appdynamics\./
        $network_signature = /eum-appdynamics\.com|appdynamics\.com/
        $code_signature2   = /com\/appdynamics\//

    condition:
        is_elf and any of them
}

rule startapp : tracker
{
    meta:
        description = "Startapp"
        author      = "Abhi"
        url         = "https://www.startapp.com"

    strings:
        $code_signature    = /com\.startapp\./
        $network_signature = /c2i\.startappnetwork\.com|c2s\.startappnetwork\.com|click\.startappservice\.com|dts\.startappservice\.com|events\.startappservice\.com|images\.startappservice\.com|imp\.startappservice\.com|info\.static\.startappservice\.com|init\.startappservice\.com|req\.startappservice\.com|soda\.startappservice\.com|startappservice\.com|va\.origin\.startappservice\.com/
        $code_signature2   = /com\/startapp\//

    condition:
        is_elf and any of them
}

rule aerserv : tracker
{
    meta:
        description = "AerServ"
        author      = "Abhi"
        url         = "https://www.aerserv.com/"

    strings:
        $code_signature    = /com\.aerserv\.sdk\./
        $network_signature = /ads\.aerserv\.com|debug\.aerserv\.com/
        $code_signature2   = /com\/aerserv\/sdk\//

    condition:
        is_elf and any of them
}

rule infonline : tracker
{
    meta:
        description = "INFOnline"
        author      = "Abhi"
        url         = "https://www.infonline.de"

    strings:
        $code_signature    = /de\.infonline\./
        $network_signature = /de\.ioam\.de/
        $code_signature2   = /de\/infonline\//

    condition:
        is_elf and any of them
}

rule mytarget : tracker
{
    meta:
        description = "myTarget"
        author      = "Abhi"
        url         = "https://target.my.com/"

    strings:
        $code_signature    = /com\.my\.target\./
        $network_signature = /.target\.my\.com/
        $code_signature2   = /com\/my\/target\//

    condition:
        is_elf and any of them
}

rule tapjoy : tracker
{
    meta:
        description = "Tapjoy"
        author      = "Abhi"
        url         = "https://www.tapjoy.com/"

    strings:
        $code_signature    = /com\.tapjoy\./
        $network_signature = /tapjoy\.com|tapjoyads\.com|www\.5rocks\.io/
        $code_signature2   = /com\/tapjoy\//

    condition:
        is_elf and any of them
}

rule mintegral : tracker
{
    meta:
        description = "Mintegral"
        author      = "Abhi"
        url         = "https://www.mintegral.com/en/"

    strings:
        $code_signature    = /com\.mintegral\.|com\.mbridge\.msdk\./
        $network_signature = /analytics\.rayjump\.com|cdn-adn\.rayjump\.com|de01\.rayjump\.com|de\.rayjump\.com|detect\.rayjump\.com|fk-mtrack\.rayjump\.com|hybird\.rayjump\.com|jssdk\.rayjump\.com|net\.rayjump\.com|online\.rayjump\.com|rayjump\.com|setting\.rayjump\.com|sg-mtrack\.rayjump\.com|sg01\.rayjump\.com|sg\.rayjump\.com|tknet\.rayjump\.com|us01\.rayjump\.com/
        $code_signature2   = /com\/mintegral\/|com\/mbridge\/msdk\//

    condition:
        is_elf and any of them
}

rule gimbal : tracker
{
    meta:
        description = "Gimbal"
        author      = "Abhi"
        url         = "https://gimbal.com/"

    strings:
        $code_signature    = /com\.gimbal\.android/
        $network_signature = /analytics-server\.gimbal\.com|api\.gimbal\.com|registration\.gimbal\.com|sdk-info\.gimbal\.com/
        $code_signature2   = /com\/gimbal\/android/

    condition:
        is_elf and any of them
}

rule conviva : tracker
{
    meta:
        description = "Conviva"
        author      = "Abhi"
        url         = "https://www.conviva.com/"

    strings:
        $code_signature    = /com\.conviva\./
        $network_signature = /cws\.conviva\.com/
        $code_signature2   = /com\/conviva\//

    condition:
        is_elf and any of them
}

rule auditude : tracker
{
    meta:
        description = "Auditude"
        author      = "Abhi"
        url         = "https://www.adobe.com/privacy/policies/auditude.html"

    strings:
        $code_signature    = /com\.auditude\.ads/
        $network_signature = /auditude\.com/
        $code_signature2   = /com\/auditude\/ads/

    condition:
        is_elf and any of them
}

rule instreamatic_adman : tracker
{
    meta:
        description = "Instreamatic (Adman)"
        author      = "Abhi"
        url         = "http://instreamatic.com/"

    strings:
        $code_signature    = /com\.instreamatic/
        $network_signature = /instreamatic\.com/
        $code_signature2   = /com\/instreamatic/

    condition:
        is_elf and any of them
}

rule gameanalytics : tracker
{
    meta:
        description = "GameAnalytics"
        author      = "Abhi"
        url         = "https://gameanalytics.com/features"

    strings:
        $code_signature    = /com\.gameanalytics\.sdk/
        $code_signature2   = /com\/gameanalytics\/sdk/

    condition:
        is_elf and any of them
}

rule instabug : tracker
{
    meta:
        description = "Instabug"
        author      = "Abhi"
        url         = "https://instabug.com/crash-reporting"

    strings:
        $code_signature    = /com\.instabug\./
        $code_signature2   = /com\/instabug\//

    condition:
        is_elf and any of them
}

rule bugsnag : tracker
{
    meta:
        description = "Bugsnag"
        author      = "Abhi"
        url         = "https://www.bugsnag.com/"

    strings:
        $code_signature    = /com\.bugsnag\./
        $code_signature2   = /com\/bugsnag\//

    condition:
        is_elf and any of them
}

rule moodmedia : tracker
{
    meta:
        description = "Moodmedia"
        author      = "Abhi"
        url         = "https://us.moodmedia.com/"

    strings:
        $code_signature    = /com\.moodmedia/
        $network_signature = /moodpresence\.com/
        $code_signature2   = /com\/moodmedia/

    condition:
        is_elf and any of them
}

rule houndify : tracker
{
    meta:
        description = "Houndify"
        author      = "Abhi"
        url         = "https://www.houndify.com/"

    strings:
        $code_signature    = /com\.hound/
        $network_signature = /houndify\.com/
        $code_signature2   = /com\/hound/

    condition:
        is_elf and any of them
}

rule openx : tracker
{
    meta:
        description = "OpenX"
        author      = "Abhi"
        url         = "https://www.openx.com/"

    strings:
        $code_signature    = /com\.openx\.view\.plugplay|com\.openx\.android_sdk_openx/
        $network_signature = /openx\.com|openx\.net|openx\.org|us-ads\.openx\.net/
        $code_signature2   = /com\/openx\/view\/plugplay|com\/openx\/android_sdk_openx/

    condition:
        is_elf and any of them
}

rule taplytics : tracker
{
    meta:
        description = "Taplytics"
        author      = "Abhi"
        url         = "https://taplytics.com"

    strings:
        $code_signature    = /com\.taplytics\.sdk/
        $network_signature = /api\.taplytics\.com|ping\.tapylitics\.com/
        $code_signature2   = /com\/taplytics\/sdk/

    condition:
        is_elf and any of them
}

rule yinzcam_sobek : tracker
{
    meta:
        description = "Yinzcam Sobek"
        author      = "Abhi"
        url         = "http://www.yinzcam.com/"

    strings:
        $code_signature    = /com\.yinzcam\.sobek/
        $network_signature = /analytics\.yinzcam\.com/
        $code_signature2   = /com\/yinzcam\/sobek/

    condition:
        is_elf and any of them
}

rule ooyala : tracker
{
    meta:
        description = "Ooyala"
        author      = "Abhi"
        url         = "https://www.ooyala.com/"

    strings:
        $code_signature    = /com\.ooyala/
        $network_signature = /ooyala\.com/
        $code_signature2   = /com\/ooyala/

    condition:
        is_elf and any of them
}

rule kiip : tracker
{
    meta:
        description = "Kiip"
        author      = "Abhi"
        url         = "https://www.ninthdecimal.com/"

    strings:
        $code_signature    = /me\.kiip\.sdk/
        $network_signature = /kiip\.me/
        $code_signature2   = /me\/kiip\/sdk/

    condition:
        is_elf and any of them
}

rule mobpower : tracker
{
    meta:
        description = "MobPower"
        author      = "Abhi"
        url         = "https://home.mobpowertech.com/"

    strings:
        $code_signature    = /com\.mobpower\./
        $network_signature = /api\.mobpowertech\.com|log\.mobpowertech\.com|mobpowertech\.com|scheme\.mobpowertech\.com/
        $code_signature2   = /com\/mobpower\//

    condition:
        is_elf and any of them
}

rule adbuddiz : tracker
{
    meta:
        description = "AdBuddiz"
        author      = "Abhi"
        url         = "http://www.adbuddiz.com/abuse?hl=fr"

    strings:
        $code_signature    = /com\.purplebrain\.adbuddiz\.sdk\./
        $network_signature = /sdk\.adbuddiz\.com/
        $code_signature2   = /com\/purplebrain\/adbuddiz\/sdk\//

    condition:
        is_elf and any of them
}

rule integral_ad_science : tracker
{
    meta:
        description = "Integral Ad Science"
        author      = "Abhi"
        url         = "https://integralads.com"

    strings:
        $code_signature    = /com\.integralads\.avid\.library/
        $network_signature = /adsafeprotected\.com|iasds01\.com|integralads\.com/
        $code_signature2   = /com\/integralads\/avid\/library/

    condition:
        is_elf and any of them
}

rule altbeacon : tracker
{
    meta:
        description = "AltBeacon"
        author      = "Abhi"
        url         = "https://altbeacon.org"

    strings:
        $code_signature    = /org\.altbeacon\.beacon\.|com\.altbeacon\.beacon\.|org\.altbeacon\.bluetooth\./
        $network_signature = /data.\altbeacon\.org/
        $code_signature2   = /org\/altbeacon\/beacon\/|com\/altbeacon\/beacon\/|org\/altbeacon\/bluetooth\//

    condition:
        is_elf and any of them
}

rule salesforce_marketing_cloud : tracker
{
    meta:
        description = "Salesforce Marketing Cloud"
        author      = "Abhi"
        url         = "https://www.salesforce.com/products/marketing-cloud/"

    strings:
        $code_signature    = /com\.salesforce\.marketingcloud/
        $code_signature2   = /com\/salesforce\/marketingcloud/

    condition:
        is_elf and any of them
}

rule mozilla_telemetry : tracker
{
    meta:
        description = "Mozilla Telemetry"
        author      = "Abhi"
        url         = "https://wiki.mozilla.org/Telemetry"

    strings:
        $code_signature    = /org\.mozilla\.telemetry|org\.mozilla\.gecko\.telemetry|mozilla\.telemetry\.glean\.|org\.mozilla\.fenix\.GleanMetrics|org\.mozilla\.fenix\.components\.metrics/
        $code_signature2   = /org\/mozilla\/telemetry|org\/mozilla\/gecko\/telemetry|mozilla\/telemetry\/glean\/|org\/mozilla\/fenix\/GleanMetrics|org\/mozilla\/fenix\/components\/metrics/

    condition:
        is_elf and any of them
}

rule nend : tracker
{
    meta:
        description = "nend"
        author      = "Abhi"
        url         = "https://nend.net/en/"

    strings:
        $code_signature    = /net\.nend\.android|net\.nend\.unity\./
        $code_signature2   = /net\/nend\/android|net\/nend\/unity\//

    condition:
        is_elf and any of them
}

rule pusher : tracker
{
    meta:
        description = "Pusher"
        author      = "Abhi"
        url         = "https://pusher.com/"

    strings:
        $code_signature    = /com\.pusher\.client\./
        $code_signature2   = /com\/pusher\/client\//

    condition:
        is_elf and any of them
}

rule freewheel : tracker
{
    meta:
        description = "FreeWheel"
        author      = "Abhi"
        url         = "http://freewheel.tv/"

    strings:
        $code_signature    = /tv\.freewheel\.ad\./
        $network_signature = /fwmrm\.net/
        $code_signature2   = /tv\/freewheel\/ad\//

    condition:
        is_elf and any of them
}

rule tnk_factory : tracker
{
    meta:
        description = "TNK Factory"
        author      = "Abhi"
        url         = "http://www.tnkfactory.com"

    strings:
        $code_signature    = /com\.tnkfactory\.ad/
        $code_signature2   = /com\/tnkfactory\/ad/

    condition:
        is_elf and any of them
}

rule axonix : tracker
{
    meta:
        description = "Axonix"
        author      = "Abhi"
        url         = "http://axonix.com/"

    strings:
        $code_signature    = /com\.axonix\.android\.sdk|com\.mobclix\.android\.sdk/
        $network_signature = /ads\.mobclix\.com|axonix\.com|data\.mobclix\.com|mobclix\.com|s\.mobclix\.com/
        $code_signature2   = /com\/axonix\/android\/sdk|com\/mobclix\/android\/sdk/

    condition:
        is_elf and any of them
}

rule gemius_heatmap : tracker
{
    meta:
        description = "Gemius HeatMap"
        author      = "Abhi"
        url         = "https://heatmap.gemius.com"

    strings:
        $code_signature    = /com\.gemius\.sdk/
        $network_signature = /gemius\.pl/
        $code_signature2   = /com\/gemius\/sdk/

    condition:
        is_elf and any of them
}

rule youappi : tracker
{
    meta:
        description = "YouAppi"
        author      = "Abhi"
        url         = "https://www.youappi.com"

    strings:
        $code_signature    = /com\.youappi\.sdk\./
        $code_signature2   = /com\/youappi\/sdk\//

    condition:
        is_elf and any of them
}

rule adobe_experience_cloud : tracker
{
    meta:
        description = "Adobe Experience Cloud"
        author      = "Abhi"
        url         = "https://www.adobe.com/experience-cloud.html"

    strings:
        $code_signature    = /com\.adobe\.marketing\.mobile/
        $code_signature2   = /com\/adobe\/marketing\/mobile/

    condition:
        is_elf and any of them
}

rule teads : tracker
{
    meta:
        description = "Teads"
        author      = "Abhi"
        url         = "https://www.teads.tv"

    strings:
        $code_signature    = /tv\.teads\.|teads\.tv\./
        $network_signature = /teads\.tv/
        $code_signature2   = /tv\/teads\/|teads\/tv\//

    condition:
        is_elf and any of them
}

rule in_loco : tracker
{
    meta:
        description = "In Loco"
        author      = "Abhi"
        url         = "https://inloco.com.br"

    strings:
        $code_signature    = /com\.inlocomedia\.android/
        $network_signature = /inlocomedia\.com/
        $code_signature2   = /com\/inlocomedia\/android/

    condition:
        is_elf and any of them
}

rule iqzone : tracker
{
    meta:
        description = "IQzone"
        author      = "Abhi"
        url         = "https://iqzone.com"

    strings:
        $code_signature    = /com\.iqzone/
        $code_signature2   = /com\/iqzone/

    condition:
        is_elf and any of them
}

rule bugfender : tracker
{
    meta:
        description = "Bugfender"
        author      = "Abhi"
        url         = "https://bugfender.com/"

    strings:
        $code_signature    = /com\.bugfender\.sdk\./
        $code_signature2   = /com\/bugfender\/sdk\//

    condition:
        is_elf and any of them
}

rule wootric : tracker
{
    meta:
        description = "Wootric"
        author      = "Abhi"
        url         = "http://wootric.com"

    strings:
        $code_signature    = /com\.wootric\.androidsdk\./
        $network_signature = /.wootric\.com\.herokudns\.com|wootric\.com/
        $code_signature2   = /com\/wootric\/androidsdk\//

    condition:
        is_elf and any of them
}

rule kidoz : tracker
{
    meta:
        description = "KIDOZ"
        author      = "Abhi"
        url         = "https://kidoz.net/kidoz-sdk/"

    strings:
        $code_signature    = /com\.kidoz\.sdk/
        $code_signature2   = /com\/kidoz\/sdk/

    condition:
        is_elf and any of them
}

rule pubmatic : tracker
{
    meta:
        description = "PubMatic"
        author      = "Abhi"
        url         = "https://pubmatic.com/"

    strings:
        $code_signature    = /com\.pubmatic\.sdk/
        $network_signature = /ads\.pubmatic\.com|aktrack\.pubmatic\.com|gads\.pubmatic\.com|image2\.pubmatic\.com|simage2\.pubmatic\.com/
        $code_signature2   = /com\/pubmatic\/sdk/

    condition:
        is_elf and any of them
}

rule kissmetrics : tracker
{
    meta:
        description = "Kissmetrics"
        author      = "Abhi"
        url         = "https://www.kissmetricshq.com/"

    strings:
        $code_signature    = /com\.kissmetrics/
        $code_signature2   = /com\/kissmetrics/

    condition:
        is_elf and any of them
}

rule microsoft_visual_studio_app_center_crashes : tracker
{
    meta:
        description = "Microsoft Visual Studio App Center Crashes"
        author      = "Abhi"
        url         = "https://appcenter.ms/"

    strings:
        $code_signature    = /com\.microsoft\.appcenter\.crashes/
        $code_signature2   = /com\/microsoft\/appcenter\/crashes/

    condition:
        is_elf and any of them
}

rule webtrekk : tracker
{
    meta:
        description = "Webtrekk"
        author      = "Abhi"
        url         = "https://www.webtrekk.com/"

    strings:
        $code_signature    = /com\.webtrekk\.webtrekksdk/
        $code_signature2   = /com\/webtrekk\/webtrekksdk/

    condition:
        is_elf and any of them
}

rule google_analytics_plugin_cordova : tracker
{
    meta:
        description = "G. Analytics Plugin (Cordova)"
        author      = "Abhi"
        url         = "https://analytics.withgoogle.com/"

    strings:
        $code_signature    = /com\.danielcwilson\.plugins\.analytics/
        $code_signature2   = /com\/danielcwilson\/plugins\/analytics/

    condition:
        is_elf and any of them
}

rule bugsee : tracker
{
    meta:
        description = "Bugsee"
        author      = "Abhi"
        url         = "https://www.bugsee.com/"

    strings:
        $code_signature    = /com\.bugsee\.library\.Bugsee/
        $code_signature2   = /com\/bugsee\/library\/Bugsee/

    condition:
        is_elf and any of them
}

rule splunk_mint : tracker
{
    meta:
        description = "Splunk MINT"
        author      = "Abhi"
        url         = "https://mint.splunk.com/"

    strings:
        $code_signature    = /com\.splunk\.mint/
        $code_signature2   = /com\/splunk\/mint/

    condition:
        is_elf and any of them
}

rule microsoft_visual_studio_app_center_analytics : tracker
{
    meta:
        description = "Microsoft Visual Studio App Center Analytics"
        author      = "Abhi"
        url         = "https://appcenter.ms/"

    strings:
        $code_signature    = /com\.microsoft\.appcenter\.analytics|com\.microsoft\.azure\.mobile\.analytics/
        $code_signature2   = /com\/microsoft\/appcenter\/analytics|com\/microsoft\/azure\/mobile\/analytics/

    condition:
        is_elf and any of them
}

rule nielsen : tracker
{
    meta:
        description = "Nielsen"
        author      = "Abhi"
        url         = "https://www.nielsen.com"

    strings:
        $code_signature    = /com\.nielsen\.app/
        $code_signature2   = /com\/nielsen\/app/

    condition:
        is_elf and any of them
}

rule reveal_mobile : tracker
{
    meta:
        description = "Reveal Mobile"
        author      = "Abhi"
        url         = "https://revealmobile.com/"

    strings:
        $code_signature    = /com\.stepleaderdigital\.reveal/
        $code_signature2   = /com\/stepleaderdigital\/reveal/

    condition:
        is_elf and any of them
}

rule repro : tracker
{
    meta:
        description = "Repro"
        author      = "Abhi"
        url         = "https://repro.io/"

    strings:
        $code_signature    = /io\.repro\.android\./
        $code_signature2   = /io\/repro\/android\//

    condition:
        is_elf and any of them
}

rule sensors_analytics : tracker
{
    meta:
        description = "Sensors Analytics"
        author      = "Abhi"
        url         = "https://www.sensorsdata.cn"

    strings:
        $code_signature    = /com\.sensorsdata\.analytics\.android\.sdk/
        $code_signature2   = /com\/sensorsdata\/analytics\/android\/sdk/

    condition:
        is_elf and any of them
}

rule tenjin : tracker
{
    meta:
        description = "Tenjin"
        author      = "Abhi"
        url         = "https://www.tenjin.com/"

    strings:
        $code_signature    = /com\.tenjin\.android\./
        $code_signature2   = /com\/tenjin\/android\//

    condition:
        is_elf and any of them
}

rule tapstream : tracker
{
    meta:
        description = "Tapstream"
        author      = "Abhi"
        url         = "https://www.tapstream.com/"

    strings:
        $code_signature    = /com\.tapstream\.sdk/
        $code_signature2   = /com\/tapstream\/sdk/

    condition:
        is_elf and any of them
}

rule singular : tracker
{
    meta:
        description = "Singular"
        author      = "Abhi"
        url         = "https://singular.net/"

    strings:
        $code_signature    = /com\.singular\.sdk/
        $code_signature2   = /com\/singular\/sdk/

    condition:
        is_elf and any of them
}

rule calldorado : tracker
{
    meta:
        description = "CallDorado"
        author      = "Abhi"
        url         = "http://calldorado.com"

    strings:
        $code_signature    = /com\.calldorado\.android/
        $code_signature2   = /com\/calldorado\/android/

    condition:
        is_elf and any of them
}

rule uxcam : tracker
{
    meta:
        description = "UXCam"
        author      = "Abhi"
        url         = "https://uxcam.com/"

    strings:
        $code_signature    = /com\.uxcam\./
        $network_signature = /verify.uxcam.com/
        $code_signature2   = /com\/uxcam\//

    condition:
        is_elf and any of them
}

rule upsight : tracker
{
    meta:
        description = "Upsight"
        author      = "Abhi"
        url         = "https://www.upsight.com/"

    strings:
        $code_signature    = /com\.upsight\.android/
        $code_signature2   = /com\/upsight\/android/

    condition:
        is_elf and any of them
}

rule appcelerator_analytics : tracker
{
    meta:
        description = "Appcelerator Analytics"
        author      = "Abhi"
        url         = "https://www.appcelerator.com"

    strings:
        $code_signature    = /com\.appcelerator\.aps\.|org\.appcelerator\.titanium\.analytics/
        $network_signature = /appcelerator\.com|appcelerator\.net/
        $code_signature2   = /com\/appcelerator\/aps\/|org\/appcelerator\/titanium\/analytics/

    condition:
        is_elf and any of them
}

rule adbrix : tracker
{
    meta:
        description = "Adbrix"
        author      = "Abhi"
        url         = "http://ad-brix.com/"

    strings:
        $code_signature    = /com\.igaworks\.adbrix/
        $network_signature = /ad-brix\.com/
        $code_signature2   = /com\/igaworks\/adbrix/

    condition:
        is_elf and any of them
}

rule cauly : tracker
{
    meta:
        description = "Cauly"
        author      = "Abhi"
        url         = "https://www.cauly.net"

    strings:
        $code_signature    = /com\.fsn\.cauly|com\.trid\.tridad|com\.cauly\.android\.ad\./
        $network_signature = /ad\.cauly\.co\.kr/
        $code_signature2   = /com\/fsn\/cauly|com\/trid\/tridad|com\/cauly\/android\/ad\//

    condition:
        is_elf and any of them
}

rule tapdaq : tracker
{
    meta:
        description = "Tapdaq"
        author      = "Abhi"
        url         = "https://www.tapdaq.com/"

    strings:
        $code_signature    = /com\.tapdaq\.sdk\.|com\.tapdaq\.adapters\./
        $network_signature = /ads\.tapdaq\.com/
        $code_signature2   = /com\/tapdaq\/sdk\/|com\/tapdaq\/adapters\//

    condition:
        is_elf and any of them
}

rule verve : tracker
{
    meta:
        description = "Verve"
        author      = "Abhi"
        url         = "https://www.verve.com"

    strings:
        $code_signature    = /com\.vervewireless\.advert\./
        $code_signature2   = /com\/vervewireless\/advert\//

    condition:
        is_elf and any of them
}

rule apsalar : tracker
{
    meta:
        description = "Apsalar"
        author      = "Abhi"
        url         = "https://singular.net"

    strings:
        $code_signature    = /com\.apsalar\.sdk\./
        $network_signature = /e-ssl\.apsalar\.com|e\.apsalar\.com/
        $code_signature2   = /com\/apsalar\/sdk\//

    condition:
        is_elf and any of them
}

rule pingstart : tracker
{
    meta:
        description = "PingStart"
        author      = "Abhi"
        url         = "http://pingstart.com"

    strings:
        $code_signature    = /com\.pingstart\.adsdk\./
        $network_signature = /api\.pingstart\.com/
        $code_signature2   = /com\/pingstart\/adsdk\//

    condition:
        is_elf and any of them
}

rule keen : tracker
{
    meta:
        description = "Keen"
        author      = "Abhi"
        url         = "https://keen.io"

    strings:
        $code_signature    = /io\.keen\.client\./
        $network_signature = /api\.keen\.io/
        $code_signature2   = /io\/keen\/client\//

    condition:
        is_elf and any of them
}

rule revmob : tracker
{
    meta:
        description = "Revmob"
        author      = "Abhi"
        url         = "https://www.crunchbase.com/organization/revmob"

    strings:
        $code_signature    = /com\.revmob\.ads\./
        $code_signature2   = /com\/revmob\/ads\//

    condition:
        is_elf and any of them
}

rule emarsys_predict : tracker
{
    meta:
        description = "Emarsys Predict"
        author      = "Abhi"
        url         = "https://help.emarsys.com/hc/categories/115000670425-Predict"

    strings:
        $code_signature    = /com\.emarsys\.predict/
        $network_signature = /recommender\.scarabresearch\.com/
        $code_signature2   = /com\/emarsys\/predict/

    condition:
        is_elf and any of them
}

rule lotame : tracker
{
    meta:
        description = "Lotame"
        author      = "Abhi"
        url         = "https://www.lotame.com/"

    strings:
        $code_signature    = /com\.lotame\.android/
        $network_signature = /ad\.crwdcntrl\.net/
        $code_signature2   = /com\/lotame\/android/

    condition:
        is_elf and any of them
}

rule followanalytics : tracker
{
    meta:
        description = "FollowAnalytics"
        author      = "Abhi"
        url         = "https://www.followanalytics.com"

    strings:
        $code_signature    = /com\.followanalytics\./
        $network_signature = /sdk\.follow-apps\.com/
        $code_signature2   = /com\/followanalytics\//

    condition:
        is_elf and any of them
}

rule chartbeat : tracker
{
    meta:
        description = "Chartbeat"
        author      = "Abhi"
        url         = "https://chartbeat.com/"

    strings:
        $code_signature    = /com\.chartbeat\.androidsdk/
        $network_signature = /.chartbeat\.com|.chartbeat\.net/
        $code_signature2   = /com\/chartbeat\/androidsdk/

    condition:
        is_elf and any of them
}

rule moengage : tracker
{
    meta:
        description = "MoEngage"
        author      = "Abhi"
        url         = "https://www.moengage.com/"

    strings:
        $code_signature    = /com\.moengage\./
        $network_signature = /apiv2\.moengage\.com/
        $code_signature2   = /com\/moengage\//

    condition:
        is_elf and any of them
}

rule altamob : tracker
{
    meta:
        description = "Altamob"
        author      = "Abhi"
        url         = "https://www.altamob.com/en/index.html"

    strings:
        $code_signature    = /com\.altamob\.sdk/
        $network_signature = /api\.altamob\.com/
        $code_signature2   = /com\/altamob\/sdk/

    condition:
        is_elf and any of them
}

rule tealeaf : tracker
{
    meta:
        description = "Tealeaf"
        author      = "Abhi"
        url         = "https://acoustic.co/products/experience-analytics/"

    strings:
        $code_signature    = /com\.tl\.uic\.Tealeaf/
        $code_signature2   = /com\/tl\/uic\/Tealeaf/

    condition:
        is_elf and any of them
}

rule amoad : tracker
{
    meta:
        description = "AMoAd"
        author      = "Abhi"
        url         = "https://www.amoad.com"

    strings:
        $code_signature    = /com\.amoad\./
        $code_signature2   = /com\/amoad\//

    condition:
        is_elf and any of them
}

rule adadapted : tracker
{
    meta:
        description = "AdAdapted"
        author      = "Abhi"
        url         = "https://www.adadapted.com"

    strings:
        $code_signature    = /com\.adadapted\.android\.sdk\./
        $network_signature = /ads\.adadapted\.com/
        $code_signature2   = /com\/adadapted\/android\/sdk\//

    condition:
        is_elf and any of them
}

rule admuing : tracker
{
    meta:
        description = "AdMuing"
        author      = "Abhi"
        url         = "https://github.com/admuing"

    strings:
        $code_signature    = /com\.admuing\.danmaku\./
        $code_signature2   = /com\/admuing\/danmaku\//

    condition:
        is_elf and any of them
}

rule adcash : tracker
{
    meta:
        description = "Adcash"
        author      = "Abhi"
        url         = "https://adcash.com"

    strings:
        $code_signature    = /com\.adcash\.mobileads\./
        $code_signature2   = /com\/adcash\/mobileads\//

    condition:
        is_elf and any of them
}

rule admixer : tracker
{
    meta:
        description = "Admixer"
        author      = "Abhi"
        url         = "http://admixer.co.kr/"

    strings:
        $code_signature    = /com\.admixer|net\.admixer\.sdk/
        $network_signature = /admixer\.co\.kr|admixer\.net/
        $code_signature2   = /com\/admixer|net\/admixer\/sdk/

    condition:
        is_elf and any of them
}

rule admost : tracker
{
    meta:
        description = "Admost"
        author      = "Abhi"
        url         = "https://admost.com/"

    strings:
        $code_signature    = /admost\.sdk\.|admost\.adserver\./
        $network_signature = /cdn\-api\.admost\.com|go\.admost\.com|med\-api\.admost\.com/
        $code_signature2   = /admost\/sdk\/|admost\/adserver\//

    condition:
        is_elf and any of them
}

rule alohalytics : tracker
{
    meta:
        description = "Alohalytics"
        author      = "Abhi"
        url         = "https://github.com/biodranik/Alohalytics"

    strings:
        $code_signature    = /org\.alohalytics\./
        $code_signature2   = /org\/alohalytics\//

    condition:
        is_elf and any of them
}

rule amobee : tracker
{
    meta:
        description = "Amobee"
        author      = "Abhi"
        url         = "https://amobee.com"

    strings:
        $code_signature    = /com\.amobee\./
        $network_signature = /amobee\.com/
        $code_signature2   = /com\/amobee\//

    condition:
        is_elf and any of them
}

rule anagog : tracker
{
    meta:
        description = "Anagog"
        author      = "Abhi"
        url         = "https://anagog.com"

    strings:
        $code_signature    = /com\.anagog\.jedai/
        $code_signature2   = /com\/anagog\/jedai/

    condition:
        is_elf and any of them
}

rule bazaarvoice : tracker
{
    meta:
        description = "Bazaarvoice"
        author      = "Abhi"
        url         = "https://www.bazaarvoice.com/"

    strings:
        $code_signature    = /com\.bazaarvoice\.bvandroidsdk/
        $code_signature2   = /com\/bazaarvoice\/bvandroidsdk/

    condition:
        is_elf and any of them
}

rule beaconsinspace_fysical : tracker
{
    meta:
        description = "BeaconsInSpace (Fysical)"
        author      = "Abhi"
        url         = "https://beaconsinspace.com"

    strings:
        $code_signature    = /com\.beaconsinspace\.android\.beacon\.detector\./
        $code_signature2   = /com\/beaconsinspace\/android\/beacon\/detector\//

    condition:
        is_elf and any of them
}

rule conversant : tracker
{
    meta:
        description = "Conversant"
        author      = "Abhi"
        url         = "https://www.conversantmedia.com"

    strings:
        $code_signature    = /com\.conversantmedia|com\.greystripe\.android\./
        $network_signature = /conversantmedia\.com/
        $code_signature2   = /com\/conversantmedia|com\/greystripe\/android\//

    condition:
        is_elf and any of them
}

rule glympse : tracker
{
    meta:
        description = "Glympse"
        author      = "Abhi"
        url         = "https://glympse.com"

    strings:
        $code_signature    = /com\.glympse\.android\./
        $network_signature = /\.glympse\.com/
        $code_signature2   = /com\/glympse\/android\//

    condition:
        is_elf and any of them
}

rule herow : tracker
{
    meta:
        description = "Herow"
        author      = "Abhi"
        url         = "https://herow.io/"

    strings:
        $code_signature    = /com\.connecthings\.herow/
        $code_signature2   = /com\/connecthings\/herow/

    condition:
        is_elf and any of them
}

rule placer : tracker
{
    meta:
        description = "Placer"
        author      = "Abhi"
        url         = "https://placer.io/"

    strings:
        $code_signature    = /com\.placer\.client\.Placer/
        $code_signature2   = /com\/placer\/client\/Placer/

    condition:
        is_elf and any of them
}

rule pushspring : tracker
{
    meta:
        description = "PushSpring"
        author      = "Abhi"
        url         = "http://www.pushspring.com/"

    strings:
        $code_signature    = /com\.pushspring\.sdk\.PushSpring/
        $network_signature = /api\.pushspring\.com/
        $code_signature2   = /com\/pushspring\/sdk\/PushSpring/

    condition:
        is_elf and any of them
}

rule pyze : tracker
{
    meta:
        description = "Pyze"
        author      = "Abhi"
        url         = "https://pyze.com/"

    strings:
        $code_signature    = /com\.pyze\./
        $network_signature = /pyze\.com/
        $code_signature2   = /com\/pyze\//

    condition:
        is_elf and any of them
}

rule radar : tracker
{
    meta:
        description = "Radar"
        author      = "Abhi"
        url         = "https://radar.io/"

    strings:
        $code_signature    = /io\.radar\.sdk\.Radar/
        $code_signature2   = /io\/radar\/sdk\/Radar/

    condition:
        is_elf and any of them
}

rule sentiance : tracker
{
    meta:
        description = "Sentiance"
        author      = "Abhi"
        url         = "https://www.sentiance.com/"

    strings:
        $code_signature    = /com\.sentiance\.sdk\./
        $network_signature = /api\.sentiance\.com/
        $code_signature2   = /com\/sentiance\/sdk\//

    condition:
        is_elf and any of them
}

rule smartlook : tracker
{
    meta:
        description = "SmartLook"
        author      = "Abhi"
        url         = "https://www.smartlook.com/"

    strings:
        $code_signature    = /com\.smartlook\.sdk\.smartlook\./
        $network_signature = /smartlook\.com/
        $code_signature2   = /com\/smartlook\/sdk\/smartlook\//

    condition:
        is_elf and any of them
}

rule square_metrics : tracker
{
    meta:
        description = "Square Metrics"
        author      = "Abhi"
        url         = "https://www.squaremetrics.com"

    strings:
        $code_signature    = /com\.beaconinside\.proximitysdk\.ProximityService/
        $network_signature = /api\.beaconinside\.com/
        $code_signature2   = /com\/beaconinside\/proximitysdk\/ProximityService/

    condition:
        is_elf and any of them
}

rule talkingdata : tracker
{
    meta:
        description = "TalkingData"
        author      = "Abhi"
        url         = "https://www.talkingdata.com/"

    strings:
        $code_signature    = /com\.talkingdata\.sdk\.|com\.tendcloud\.tenddata\.|com\.talkingdata\.appanalytics\.|com\.talkingdata\.adtracking\.|com\.tendcloud\.appcpa\.|com\.apptalkingdata\.push\.|com\.gametalkingdata\.push\./
        $network_signature = /account\.talkingdata\.com|av1\.xdrig\.com|cloud\.xdrig\.com|m\.talkingdata\.com|push\.xdrig\.com/
        $code_signature2   = /com\/talkingdata\/sdk\/|com\/tendcloud\/tenddata\/|com\/talkingdata\/appanalytics\/|com\/talkingdata\/adtracking\/|com\/tendcloud\/appcpa\/|com\/apptalkingdata\/push\/|com\/gametalkingdata\/push\//

    condition:
        is_elf and any of them
}

rule flymob : tracker
{
    meta:
        description = "flymob"
        author      = "Abhi"
        url         = "https://flymob.com/"

    strings:
        $code_signature    = /com\.flymob\.sdk\./
        $code_signature2   = /com\/flymob\/sdk\//

    condition:
        is_elf and any of them
}

rule adfalcon : tracker
{
    meta:
        description = "AdFalcon"
        author      = "Abhi"
        url         = "http://adfalcon.com"

    strings:
        $code_signature    = /com\.noqoush\.adfalcon\.android\.sdk/
        $code_signature2   = /com\/noqoush\/adfalcon\/android\/sdk/

    condition:
        is_elf and any of them
}

rule bitly : tracker
{
    meta:
        description = "Bitly"
        author      = "Abhi"
        url         = "https://bitly.com/"

    strings:
        $code_signature    = /com\.bitly\.Bitly/
        $code_signature2   = /com\/bitly\/Bitly/

    condition:
        is_elf and any of them
}

rule enhance : tracker
{
    meta:
        description = "Enhance"
        author      = "Abhi"
        url         = "https://enhance.co"

    strings:
        $code_signature    = /co\.enhance\.Enhance/
        $network_signature = /app-config\.enhance\.co|data-location\.enhance\.co/
        $code_signature2   = /co\/enhance\/Enhance/

    condition:
        is_elf and any of them
}

rule esri_arcgis : tracker
{
    meta:
        description = "Esri ArcGIS"
        author      = "Abhi"
        url         = "https://www.arcgis.com/"

    strings:
        $code_signature    = /com\.esri\.arcgisruntime\./
        $code_signature2   = /com\/esri\/arcgisruntime\//

    condition:
        is_elf and any of them
}

rule giphy_analytics : tracker
{
    meta:
        description = "GIPHY Analytics"
        author      = "Abhi"
        url         = "https://giphy.com/"

    strings:
        $code_signature    = /com\.giphy\.sdk\.analytics|com\.giphy\.sdk\.tracking/
        $network_signature = /api\.giphy\.com|pingback\.giphy\.com/
        $code_signature2   = /com\/giphy\/sdk\/analytics|com\/giphy\/sdk\/tracking/

    condition:
        is_elf and any of them
}

rule heap : tracker
{
    meta:
        description = "Heap"
        author      = "Abhi"
        url         = "https://heap.io/"

    strings:
        $code_signature    = /com\.heapanalytics/
        $network_signature = /heapanalytics.com/
        $code_signature2   = /com\/heapanalytics/

    condition:
        is_elf and any of them
}

rule inneractive : tracker
{
    meta:
        description = "Inneractive"
        author      = "Abhi"
        url         = "https://www.crunchbase.com/organization/inneractive"

    strings:
        $code_signature    = /com\.inneractive\.api\.ads/
        $code_signature2   = /com\/inneractive\/api\/ads/

    condition:
        is_elf and any of them
}

rule mdotm : tracker
{
    meta:
        description = "MDOTM"
        author      = "Abhi"
        url         = "http://mdotm.com/"

    strings:
        $code_signature    = /com\.mdotm\.android/
        $network_signature = /ads\.mdotm\.com/
        $code_signature2   = /com\/mdotm\/android/

    condition:
        is_elf and any of them
}

rule metaps : tracker
{
    meta:
        description = "Metaps"
        author      = "Abhi"
        url         = "http://www.metaps.com"

    strings:
        $code_signature    = /com\.metaps/
        $code_signature2   = /com\/metaps/

    condition:
        is_elf and any of them
}

rule parse_ly : tracker
{
    meta:
        description = "Parse.ly"
        author      = "Abhi"
        url         = "https://www.parse.ly/"

    strings:
        $code_signature    = /com\.parsely\.parselyandroid/
        $code_signature2   = /com\/parsely\/parselyandroid/

    condition:
        is_elf and any of them
}

rule pollfish : tracker
{
    meta:
        description = "Pollfish"
        author      = "Abhi"
        url         = "https://www.pollfish.com"

    strings:
        $code_signature    = /com\.pollfish/
        $code_signature2   = /com\/pollfish/

    condition:
        is_elf and any of them
}

rule qualtrics : tracker
{
    meta:
        description = "Qualtrics"
        author      = "Abhi"
        url         = "http://www.qualtrics.com/"

    strings:
        $code_signature    = /com\.qualtrics\.digital\./
        $network_signature = /qualtrics\.com/
        $code_signature2   = /com\/qualtrics\/digital\//

    condition:
        is_elf and any of them
}

rule tamoco : tracker
{
    meta:
        description = "Tamoco"
        author      = "Abhi"
        url         = "https://www.tamoco.com/"

    strings:
        $code_signature    = /com\.tamoco\.sdk/
        $network_signature = /evt\.tamoco\.com/
        $code_signature2   = /com\/tamoco\/sdk/

    condition:
        is_elf and any of them
}

rule vpon : tracker
{
    meta:
        description = "Vpon"
        author      = "Abhi"
        url         = "https://www.vpon.com/"

    strings:
        $code_signature    = /com\.vpon\.ads|com\.vpadn\.analytics|com\.vpadn\.ads\.|com\.vpadn\.widget\./
        $code_signature2   = /com\/vpon\/ads|com\/vpadn\/analytics|com\/vpadn\/ads\/|com\/vpadn\/widget\//

    condition:
        is_elf and any of them
}

rule yume : tracker
{
    meta:
        description = "YuMe"
        author      = "Abhi"
        url         = "https://www.appbrain.com/stats/libraries/details/yume/yume"

    strings:
        $code_signature    = /com\.yume\.android/
        $code_signature2   = /com\/yume\/android/

    condition:
        is_elf and any of them
}

rule zapr : tracker
{
    meta:
        description = "Zapr"
        author      = "Abhi"
        url         = "https://www.zapr.in/"

    strings:
        $code_signature    = /com\.redbricklane\.zapr/
        $network_signature = /.zapr\.in/
        $code_signature2   = /com\/redbricklane\/zapr/

    condition:
        is_elf and any of them
}

rule mediba : tracker
{
    meta:
        description = "mediba"
        author      = "Abhi"
        url         = "https://www.mediba.jp"

    strings:
        $code_signature    = /com\.mediba\.jp|mediba\.ad\.sdk\.android\.openx/
        $code_signature2   = /com\/mediba\/jp|mediba\/ad\/sdk\/android\/openx/

    condition:
        is_elf and any of them
}

rule google_admob : tracker
{
    meta:
        description = "G. AdMob"
        author      = "Abhi"
        url         = "https://admob.google.com"

    strings:
        $code_signature    = /com\.google\.ads\.|com\.google\.android\.gms\.ads\.AdView|com\.google\.android\.gms\.ads\.AdActivity|com\.google\.android\.gms\.ads\.AdRequest|com\.google\.android\.gms\.ads\.mediation|com\.google\.android\.gms\.ads\.doubleclick|com\.google\.android\.ads\.|com\.google\.unity\.ads\.|com\.google\.android\.gms\.admob|com\.google\.firebase\.firebase_ads\./
        $network_signature = /2mdn\.net|dmtry\.com|doubleclick\.com|doubleclick\.net|mng-ads\.com|mobileads\.google\.com|ads\.google\.com|googlesyndication\.com|googleadservices\.com|googleads\.g\.doubleclick\.net|adservice\.google\..*|adservice\.g\.cn/
        $code_signature2   = /com\/google\/ads\/|com\/google\/android\/gms\/ads\/AdView|com\/google\/android\/gms\/ads\/AdActivity|com\/google\/android\/gms\/ads\/AdRequest|com\/google\/android\/gms\/ads\/mediation|com\/google\/android\/gms\/ads\/doubleclick|com\/google\/android\/ads\/|com\/google\/unity\/ads\/|com\/google\/android\/gms\/admob|com\/google\/firebase\/firebase_ads\//

    condition:
        is_elf and any of them
}

rule unacast_pure : tracker
{
    meta:
        description = "Unacast Pure"
        author      = "Abhi"
        url         = "https://www.unacast.com/"

    strings:
        $code_signature    = /com\.pure\.internal\.|com\.pure\.sdk\./
        $code_signature2   = /com\/pure\/internal\/|com\/pure\/sdk\//

    condition:
        is_elf and any of them
}

rule factual : tracker
{
    meta:
        description = "Factual"
        author      = "Abhi"
        url         = "https://www.factual.com"

    strings:
        $code_signature    = /com\.factual\.engine|com\.factual\.Factual/
        $network_signature = /api.factual.com/
        $code_signature2   = /com\/factual\/engine|com\/factual\/Factual/

    condition:
        is_elf and any of them
}

rule footmarks : tracker
{
    meta:
        description = "Footmarks"
        author      = "Abhi"
        url         = "https://www.footmarks.com"

    strings:
        $code_signature    = /com\.footmarks\.footmarkssdkm2/
        $code_signature2   = /com\/footmarks\/footmarkssdkm2/

    condition:
        is_elf and any of them
}

rule oztam : tracker
{
    meta:
        description = "OzTAM"
        author      = "Abhi"
        url         = "https://oztam.com.au/"

    strings:
        $code_signature    = /au\.com\.oztam\./
        $network_signature = /deliver.oztam.com.au/
        $code_signature2   = /au\/com\/oztam\//

    condition:
        is_elf and any of them
}

rule receptiv_formerly_mediabrix : tracker
{
    meta:
        description = "Receptiv (formerly Mediabrix)"
        author      = "Abhi"
        url         = "https://www.receptiv.com/"

    strings:
        $code_signature    = /com\.mediabrix\.android/
        $code_signature2   = /com\/mediabrix\/android/

    condition:
        is_elf and any of them
}

rule tutela : tracker
{
    meta:
        description = "Tutela"
        author      = "Abhi"
        url         = "https://www.tutela.com/"

    strings:
        $code_signature    = /com\.tutelatechnologies\.sdk/
        $code_signature2   = /com\/tutelatechnologies\/sdk/

    condition:
        is_elf and any of them
}

rule twine_data : tracker
{
    meta:
        description = "Twine Data"
        author      = "Abhi"
        url         = "https://www.truedata.co/"

    strings:
        $code_signature    = /com\.twine\.sdk/
        $code_signature2   = /com\/twine\/sdk/

    condition:
        is_elf and any of them
}

rule verizon_ads : tracker
{
    meta:
        description = "Verizon Ads"
        author      = "Abhi"
        url         = "https://www.verizonmedia.com/"

    strings:
        $code_signature    = /com\.verizon\.ads|com\.verizondigitalmedia\.mobile\.|com\.oath\.mobile\./
        $code_signature2   = /com\/verizon\/ads|com\/verizondigitalmedia\/mobile\/|com\/oath\/mobile\//

    condition:
        is_elf and any of them
}

rule adpopcorn : tracker
{
    meta:
        description = "adPOPcorn"
        author      = "Abhi"
        url         = "https://adpopcorn.com/"

    strings:
        $code_signature    = /com\.igaworks\.adpopcorn|com\.igaworks\.ssp\./
        $code_signature2   = /com\/igaworks\/adpopcorn|com\/igaworks\/ssp\//

    condition:
        is_elf and any of them
}

rule maio_by_i_mobile : tracker
{
    meta:
        description = "maio by i-mobile"
        author      = "Abhi"
        url         = "https://adpf-info.i-mobile.co.jp/en/"

    strings:
        $code_signature    = /jp\.maio\.sdk\./
        $code_signature2   = /jp\/maio\/sdk\//

    condition:
        is_elf and any of them
}

rule __dialog : tracker
{
    meta:
        description = "360Dialog"
        author      = "Abhi"
        url         = "https://www.360dialog.com"

    strings:
        $code_signature    = /com\.threesixtydialog\.sdk\./
        $code_signature2   = /com\/threesixtydialog\/sdk\//

    condition:
        is_elf and any of them
}

rule abtasty : tracker
{
    meta:
        description = "ABTasty"
        author      = "Abhi"
        url         = "https://www.abtasty.com"

    strings:
        $code_signature    = /com\.abtasty/
        $network_signature = /abtasty\.com/
        $code_signature2   = /com\/abtasty/

    condition:
        is_elf and any of them
}

rule acrcloud : tracker
{
    meta:
        description = "ACRCloud"
        author      = "Abhi"
        url         = "https://acrcloud.com/"

    strings:
        $code_signature    = /com\.acrcloud/
        $network_signature = /acrcloud.com|hb-minify-juc1ugur1qwqqqo4.stackpathdns.com/
        $code_signature2   = /com\/acrcloud/

    condition:
        is_elf and any of them
}

rule aarki : tracker
{
    meta:
        description = "Aarki"
        author      = "Abhi"
        url         = "https://www.aarki.com"

    strings:
        $code_signature    = /com\.aarki/
        $code_signature2   = /com\/aarki/

    condition:
        is_elf and any of them
}

rule actv_me : tracker
{
    meta:
        description = "Actv8me"
        author      = "Abhi"
        url         = "https://www.actv8me.com/"

    strings:
        $code_signature    = /me\.actv8/
        $network_signature = /actv8technologies\.com/
        $code_signature2   = /me\/actv8/

    condition:
        is_elf and any of them
}

rule iab_open_measurement : tracker
{
    meta:
        description = "IAB Open Measurement"
        author      = "Abhi"
        url         = "https://iabtechlab.com/"

    strings:
        $code_signature    = /com\.iab\.omid\.library|com\.prime31\.util\.IabHelperImpl|com\.prime31\.IAB\./
        $code_signature2   = /com\/iab\/omid\/library|com\/prime31\/util\/IabHelperImpl|com\/prime31\/IAB\//

    condition:
        is_elf and any of them
}

rule huawei_mobile_services_hms_core : tracker
{
    meta:
        description = "Huawei Mobile Services (HMS) Core"
        author      = "Abhi"
        url         = "https://developer.huawei.com/consumer/en/hms"

    strings:
        $code_signature    = /com\.huawei\.hms\.analytics|com\.huawei\.hms\.location|com\.huawei\.hms\.plugin\.analytics|com\.huawei\.hms\.plugin\.ads|com\.huawei\.updatesdk\.|com\.huawei\.agconnect\.|com\.huawei\.hms\.support\.api\.push\.|com\.huawei\.hms\.flutter\.analytics\./
        $network_signature = /hicloud\.com|dbankcloud\.ru|dbankcloud\.cn|dbankcloud\.com/
        $code_signature2   = /com\/huawei\/hms\/analytics|com\/huawei\/hms\/location|com\/huawei\/hms\/plugin\/analytics|com\/huawei\/hms\/plugin\/ads|com\/huawei\/updatesdk\/|com\/huawei\/agconnect\/|com\/huawei\/hms\/support\/api\/push\/|com\/huawei\/hms\/flutter\/analytics\//

    condition:
        is_elf and any of them
}

rule akamai_map : tracker
{
    meta:
        description = "Akamai MAP"
        author      = "Abhi"
        url         = "https://www.akamai.com/"

    strings:
        $code_signature    = /com\.akamai\.android\.sdk\.AkaMap/
        $code_signature2   = /com\/akamai\/android\/sdk\/AkaMap/

    condition:
        is_elf and any of them
}

rule mail_ru : tracker
{
    meta:
        description = "Mail.ru"
        author      = "Abhi"
        url         = "http://mail.ru"

    strings:
        $code_signature    = /ru\.mail\.mrgservice\.advertising|ru\.mail\.mrgservice\.analytics/
        $code_signature2   = /ru\/mail\/mrgservice\/advertising|ru\/mail\/mrgservice\/analytics/

    condition:
        is_elf and any of them
}

rule airpush : tracker
{
    meta:
        description = "Airpush"
        author      = "Abhi"
        url         = "https://airpush.com/"

    strings:
        $code_signature    = /com\.airpush\./
        $network_signature = /api\.airpush\.com|apidm\.airpush\.com|apistaging\.airpush\.com|apportal\.airpush\.com|appwall\.api\.airpush\.com|beta\.airpush\.com|cdnap\.airpush\.com|m\.airpush\.com/
        $code_signature2   = /com\/airpush\//

    condition:
        is_elf and any of them
}

rule alimama_formerly_adsmogo : tracker
{
    meta:
        description = "Alimama (formerly AdsMogo)"
        author      = "Abhi"
        url         = "https://www.alimama.com/"

    strings:
        $code_signature    = /com\.adsmogo\.|com\.alimama\./
        $network_signature = /\.alimama\.|\.adsmogo\./
        $code_signature2   = /com\/adsmogo\/|com\/alimama\//

    condition:
        is_elf and any of them
}

rule anysdk : tracker
{
    meta:
        description = "AnySDK"
        author      = "Abhi"
        url         = "http://www.anysdk.com/"

    strings:
        $code_signature    = /com\.anysdk\.framework\.AnalyticsWrapper|com\.anysdk\.framework\.AdsWrapper/
        $code_signature2   = /com\/anysdk\/framework\/AnalyticsWrapper|com\/anysdk\/framework\/AdsWrapper/

    condition:
        is_elf and any of them
}

rule button : tracker
{
    meta:
        description = "Button"
        author      = "Abhi"
        url         = "https://www.usebutton.com"

    strings:
        $code_signature    = /com\.usebutton\.sdk\./
        $network_signature = /\.usebutton.com/
        $code_signature2   = /com\/usebutton\/sdk\//

    condition:
        is_elf and any of them
}

rule carto_formerly_nutiteq : tracker
{
    meta:
        description = "Carto (formerly Nutiteq)"
        author      = "Abhi"
        url         = "https://carto.com"

    strings:
        $code_signature    = /com\.nutiteq|com\.carto/
        $code_signature2   = /com\/nutiteq|com\/carto/

    condition:
        is_elf and any of them
}

rule didomi : tracker
{
    meta:
        description = "Didomi"
        author      = "Abhi"
        url         = "https://www.didomi.io/"

    strings:
        $code_signature    = /io\.didomi\.sdk\./
        $code_signature2   = /io\/didomi\/sdk\//

    condition:
        is_elf and any of them
}

rule jiguang_aurora_mobile_jpush : tracker
{
    meta:
        description = "JiGuang Aurora Mobile JPush"
        author      = "Abhi"
        url         = "https://ir.jiguang.cn/corporate-profile"

    strings:
        $code_signature    = /cn\.jpush\.android/
        $network_signature = /.*\.jiguang\.cn/
        $code_signature2   = /cn\/jpush\/android/

    condition:
        is_elf and any of them
}

rule jumio : tracker
{
    meta:
        description = "Jumio"
        author      = "Abhi"
        url         = "https://www.jumio.com/"

    strings:
        $code_signature    = /com\.jumio\.MobileSDK/
        $network_signature = /mobile-sdk-resources.jumio.com|nv-sdk.jumio.com/
        $code_signature2   = /com\/jumio\/MobileSDK/

    condition:
        is_elf and any of them
}

rule lenddo : tracker
{
    meta:
        description = "Lenddo"
        author      = "Abhi"
        url         = "https://www.lenddo.com/"

    strings:
        $code_signature    = /com\.lenddo\.mobile/
        $network_signature = /\.partner-service\.link/
        $code_signature2   = /com\/lenddo\/mobile/

    condition:
        is_elf and any of them
}

rule pokkt : tracker
{
    meta:
        description = "POKKT"
        author      = "Abhi"
        url         = "https://www.pokkt.com"

    strings:
        $code_signature    = /com\.pokkt\.sdk\./
        $code_signature2   = /com\/pokkt\/sdk\//

    condition:
        is_elf and any of them
}

rule prebid_mobile : tracker
{
    meta:
        description = "Prebid Mobile"
        author      = "Abhi"
        url         = "https://prebid.org"

    strings:
        $code_signature    = /org\.prebid\.mobile/
        $network_signature = /.prebid.org/
        $code_signature2   = /org\/prebid\/mobile/

    condition:
        is_elf and any of them
}

rule sk_planet_tad : tracker
{
    meta:
        description = "SK planet Tad"
        author      = "Abhi"
        url         = "https://www.skplanet.com/eng"

    strings:
        $code_signature    = /com\.skplanet\.tad/
        $code_signature2   = /com\/skplanet\/tad/

    condition:
        is_elf and any of them
}

rule split : tracker
{
    meta:
        description = "Split"
        author      = "Abhi"
        url         = "https://www.split.io/"

    strings:
        $code_signature    = /io\.split\.android\./
        $network_signature = /event.split.io|sdk.split.io/
        $code_signature2   = /io\/split\/android\//

    condition:
        is_elf and any of them
}

rule exponea : tracker
{
    meta:
        description = "Exponea"
        author      = "Abhi"
        url         = "https://exponea.com"

    strings:
        $code_signature    = /com\.infinario\.android\.infinariosdk\.|com\.exponea\.sdk|com\.sygic\.aura\./
        $network_signature = /api.infinario.com|sygic-api.infinario.com/
        $code_signature2   = /com\/infinario\/android\/infinariosdk\/|com\/exponea\/sdk|com\/sygic\/aura\//

    condition:
        is_elf and any of them
}

rule ipqualityscore : tracker
{
    meta:
        description = "IPQualityScore"
        author      = "Abhi"
        url         = "https://www.ipqualityscore.com"

    strings:
        $code_signature    = /com\.ipqualityscore\./
        $network_signature = /ipqualityscore\.com/
        $code_signature2   = /com\/ipqualityscore\//

    condition:
        is_elf and any of them
}

rule opensignal : tracker
{
    meta:
        description = "Opensignal"
        author      = "Abhi"
        url         = "https://www.opensignal.com"

    strings:
        $code_signature    = /com\.opensignal\.datacollection\./
        $code_signature2   = /com\/opensignal\/datacollection\//

    condition:
        is_elf and any of them
}

rule signalframe : tracker
{
    meta:
        description = "SignalFrame"
        author      = "Abhi"
        url         = "https://signalframe.com/"

    strings:
        $code_signature    = /com\.wirelessregistry\.observersdk\./
        $code_signature2   = /com\/wirelessregistry\/observersdk\//

    condition:
        is_elf and any of them
}

rule x_mode : tracker
{
    meta:
        description = "X-Mode"
        author      = "Abhi"
        url         = "https://xmode.io/"

    strings:
        $code_signature    = /io\.xmode\.BcnConfig|io\.xmode\.locationsdk|io\.mysdk\./
        $network_signature = /api\.myendpoint\.io|bin5y4muil\.execute-api\.us-east-1\.amazonaws\.com|api\.smartechmetrics\.com/
        $code_signature2   = /io\/xmode\/BcnConfig|io\/xmode\/locationsdk|io\/mysdk\//

    condition:
        is_elf and any of them
}

rule oneaudience : tracker
{
    meta:
        description = "OneAudience"
        author      = "Abhi"
        url         = "http://www.oneaudience.com/"

    strings:
        $code_signature    = /com\.oneaudience\.sdk\./
        $code_signature2   = /com\/oneaudience\/sdk\//

    condition:
        is_elf and any of them
}

rule openback : tracker
{
    meta:
        description = "OpenBack"
        author      = "Abhi"
        url         = "https://www.openback.com"

    strings:
        $code_signature    = /com\.openback/
        $code_signature2   = /com\/openback/

    condition:
        is_elf and any of them
}

rule predicio : tracker
{
    meta:
        description = "PredicIO"
        author      = "Abhi"
        url         = "https://www.predic.io/"

    strings:
        $code_signature    = /com\.telescope\.android|io\.predic\.tracker/
        $network_signature = /sdk\.predic\.io/
        $code_signature2   = /com\/telescope\/android|io\/predic\/tracker/

    condition:
        is_elf and any of them
}

rule adlocus : tracker
{
    meta:
        description = "AdLocus"
        author      = "Abhi"
        url         = "https://adlocus.com"

    strings:
        $code_signature    = /com\.adlocus\./
        $code_signature2   = /com\/adlocus\//

    condition:
        is_elf and any of them
}

rule adcenix : tracker
{
    meta:
        description = "Adcenix"
        author      = "Abhi"
        url         = "http://adcenix.com"

    strings:
        $code_signature    = /com\.adcenix\./
        $code_signature2   = /com\/adcenix\//

    condition:
        is_elf and any of them
}

rule admitad : tracker
{
    meta:
        description = "Admitad"
        author      = "Abhi"
        url         = "https://www.admitad.com"

    strings:
        $code_signature    = /ru\.tachos\.admitadstatisticsdk/
        $network_signature = /.*\.admitad.com/
        $code_signature2   = /ru\/tachos\/admitadstatisticsdk/

    condition:
        is_elf and any of them
}

rule autonavi__amap : tracker
{
    meta:
        description = "AutoNavi / Amap"
        author      = "Abhi"
        url         = "https://mobile.amap.com/"

    strings:
        $code_signature    = /com\.amap\.api/
        $network_signature = /grid\.amap\.com|tm\.amap\.com|mst[0-9]*\.is\.autonavi\.com|mt[0-9]*\.google\.cn|abroad\.apilocate\.amap\.com|apilocate\.amap\.com|restapi\.amap\.com|yuntuapi\.amap\.com|m5\.amap\.com|wb\.amap\.com|wb\.amap\.com|wb\.amap\.com|wb\.amap\.com|apiinit\.amap\.com|restapi\.amap\.com|logs\.amap\.com|cgicol\.amap\.com|lbs\.amap\.com|wap\.amap\.com/
        $code_signature2   = /com\/amap\/api/

    condition:
        is_elf and any of them
}

rule ibm_digital_analytics : tracker
{
    meta:
        description = "IBM Digital Analytics"
        author      = "Abhi"
        url         = "https://www.ibm.com/customer-engagement/coremetrics-software"

    strings:
        $code_signature    = /com\.digitalanalytics\./
        $network_signature = /data\.de\.coremetrics\.com/
        $code_signature2   = /com\/digitalanalytics\//

    condition:
        is_elf and any of them
}

rule pangle : tracker
{
    meta:
        description = "Pangle"
        author      = "Abhi"
        url         = "https://www.pangleglobal.com"

    strings:
        $code_signature    = /com\.bytedance|com\.pgl|com\.pangle\.global/
        $code_signature2   = /com\/bytedance|com\/pgl|com\/pangle\/global/

    condition:
        is_elf and any of them
}

rule yoc_vis_x : tracker
{
    meta:
        description = "YOC VIS.X"
        author      = "Abhi"
        url         = "https://yoc.com"

    strings:
        $code_signature    = /com\.yoc\.visx/
        $network_signature = /yoc-performance\.com|yoc\.com/
        $code_signature2   = /com\/yoc\/visx/

    condition:
        is_elf and any of them
}

rule ad_generation : tracker
{
    meta:
        description = "Ad Generation"
        author      = "Abhi"
        url         = "https://supership.jp/business/adgeneration/"

    strings:
        $code_signature    = /com\.socdm\.d\.adgeneration\./
        $code_signature2   = /com\/socdm\/d\/adgeneration\//

    condition:
        is_elf and any of them
}

rule adjoe : tracker
{
    meta:
        description = "Adjoe"
        author      = "Abhi"
        url         = "https://adjoe.io/"

    strings:
        $code_signature    = /io\.adjoe\.sdk\.|io\.adjoe\.protection\./
        $code_signature2   = /io\/adjoe\/sdk\/|io\/adjoe\/protection\//

    condition:
        is_elf and any of them
}

rule appvador : tracker
{
    meta:
        description = "AppVador"
        author      = "Abhi"
        url         = "http://www.appvador.com/"

    strings:
        $code_signature    = /com\.appvador\.ads\./
        $code_signature2   = /com\/appvador\/ads\//

    condition:
        is_elf and any of them
}

rule appodeal_stack : tracker
{
    meta:
        description = "Appodeal Stack"
        author      = "Abhi"
        url         = "https://appodealstack.com/about/"

    strings:
        $code_signature    = /com\.explorestack\./
        $code_signature2   = /com\/explorestack\//

    condition:
        is_elf and any of them
}

rule appsgeyser : tracker
{
    meta:
        description = "AppsGeyser"
        author      = "Abhi"
        url         = "https://appsgeyser.com/"

    strings:
        $code_signature    = /com\.appsgeyser\.sdk|com\.appsgeyser\.multiTabApp\.VideoPlayerActivity/
        $code_signature2   = /com\/appsgeyser\/sdk|com\/appsgeyser\/multiTabApp\/VideoPlayerActivity/

    condition:
        is_elf and any of them
}

rule bidmachine : tracker
{
    meta:
        description = "BidMachine"
        author      = "Abhi"
        url         = "https://bidmachine.io/"

    strings:
        $code_signature    = /io\.bidmachine\./
        $code_signature2   = /io\/bidmachine\//

    condition:
        is_elf and any of them
}

rule bugsense : tracker
{
    meta:
        description = "BugSense"
        author      = "Abhi"
        url         = "http://www.bugsense.com/"

    strings:
        $code_signature    = /com\.bugsense\.trace\./
        $code_signature2   = /com\/bugsense\/trace\//

    condition:
        is_elf and any of them
}

rule buzzad_benefit : tracker
{
    meta:
        description = "BuzzAd Benefit"
        author      = "Abhi"
        url         = "https://buzzvil.atlassian.net/wiki/spaces/BDG/pages/486834313/BuzzAd-Benefit+Android+SDK"

    strings:
        $code_signature    = /com\.buzzvil\./
        $code_signature2   = /com\/buzzvil\//

    condition:
        is_elf and any of them
}

rule gom_factory_adpie : tracker
{
    meta:
        description = "GOM Factory AdPie"
        author      = "Abhi"
        url         = "http://www.gomfactory.com"

    strings:
        $code_signature    = /com\.gomfactory\.adpie\./
        $code_signature2   = /com\/gomfactory\/adpie\//

    condition:
        is_elf and any of them
}

rule jumptap : tracker
{
    meta:
        description = "JumpTap"
        author      = "Abhi"
        url         = "http://www.millennialmedia.com"

    strings:
        $code_signature    = /com\.jumptap\.adtag\./
        $code_signature2   = /com\/jumptap\/adtag\//

    condition:
        is_elf and any of them
}

rule loopme : tracker
{
    meta:
        description = "LoopMe"
        author      = "Abhi"
        url         = "https://loopme.com/"

    strings:
        $code_signature    = /com\.loopme\./
        $code_signature2   = /com\/loopme\//

    condition:
        is_elf and any of them
}

rule raygun : tracker
{
    meta:
        description = "Raygun"
        author      = "Abhi"
        url         = "https://raygun.com"

    strings:
        $code_signature    = /com\.mindscapehq\.android\.raygun4android/
        $code_signature2   = /com\/mindscapehq\/android\/raygun4android/

    condition:
        is_elf and any of them
}

rule rjfun : tracker
{
    meta:
        description = "RjFun"
        author      = "Abhi"
        url         = "https://rjfun.github.io/"

    strings:
        $code_signature    = /com\.rjfun\.cordova\.ad|com\.rjfun\.cordova\.admob/
        $code_signature2   = /com\/rjfun\/cordova\/ad|com\/rjfun\/cordova\/admob/

    condition:
        is_elf and any of them
}

rule superawesome : tracker
{
    meta:
        description = "SuperAwesome"
        author      = "Abhi"
        url         = "https://www.superawesome.com/"

    strings:
        $code_signature    = /tv\.superawesome\.sdk|tv\.superawesome\.lib\./
        $code_signature2   = /tv\/superawesome\/sdk|tv\/superawesome\/lib\//

    condition:
        is_elf and any of them
}

rule tapresearch : tracker
{
    meta:
        description = "TapResearch"
        author      = "Abhi"
        url         = "https://www.tapresearch.com/"

    strings:
        $code_signature    = /com\.tapr\.sdk\.|com\.tapr\.internal\.|com\.tapr\.helpers\./
        $code_signature2   = /com\/tapr\/sdk\/|com\/tapr\/internal\/|com\/tapr\/helpers\//

    condition:
        is_elf and any of them
}

rule tappx : tracker
{
    meta:
        description = "Tappx"
        author      = "Abhi"
        url         = "https://www.tappx.com/"

    strings:
        $code_signature    = /com\.tappx\.sdk\.android/
        $code_signature2   = /com\/tappx\/sdk\/android/

    condition:
        is_elf and any of them
}

rule thinkingdata_analytics : tracker
{
    meta:
        description = "ThinkingData Analytics"
        author      = "Abhi"
        url         = "http://www.thinkingdata.cn/"

    strings:
        $code_signature    = /cn\.thinkingdata\./
        $code_signature2   = /cn\/thinkingdata\//

    condition:
        is_elf and any of them
}

rule vkontakte_sdk : tracker
{
    meta:
        description = "VKontakte SDK"
        author      = "Abhi"
        url         = "https://vksdk.github.io/vk-sdk-android/"

    strings:
        $code_signature    = /com\.vk\.sdk\.|com\.vk\.api\.sdk\./
        $code_signature2   = /com\/vk\/sdk\/|com\/vk\/api\/sdk\//

    condition:
        is_elf and any of them
}

rule virgo_mobile : tracker
{
    meta:
        description = "Virgo Mobile"
        author      = "Abhi"
        url         = "http://virgomobile.com/"

    strings:
        $code_signature    = /com\.virgo\.ads\./
        $code_signature2   = /com\/virgo\/ads\//

    condition:
        is_elf and any of them
}

rule zoho_analytics : tracker
{
    meta:
        description = "Zoho Analytics"
        author      = "Abhi"
        url         = "http://analytics.zoho.com/"

    strings:
        $code_signature    = /com\.zoho\.zanalytics\./
        $code_signature2   = /com\/zoho\/zanalytics\//

    condition:
        is_elf and any of them
}

rule fineboost : tracker
{
    meta:
        description = "fineboost"
        author      = "Abhi"
        url         = "http://www.yifants.cn/"

    strings:
        $code_signature    = /com\.fineboost\./
        $code_signature2   = /com\/fineboost\//

    condition:
        is_elf and any of them
}

rule acuant : tracker
{
    meta:
        description = "Acuant"
        author      = "Abhi"
        url         = "https://www.acuantcorp.com"

    strings:
        $code_signature    = /com\.acuant\.acuantcamera/
        $network_signature = /frm\.acuant\.net|medicscan\.acuant\.net|services\.assureid\.net/
        $code_signature2   = /com\/acuant\/acuantcamera/

    condition:
        is_elf and any of them
}

rule anvato_a_google_company : tracker
{
    meta:
        description = "Anvato (A G. Company)"
        author      = "Abhi"
        url         = "https://cloud.google.com/solutions/media-entertainment/?a=2"

    strings:
        $code_signature    = /com\.anvato\.androidsdk\./
        $network_signature = /.*\.anvato\.net/
        $code_signature2   = /com\/anvato\/androidsdk\//

    condition:
        is_elf and any of them
}

rule blesh : tracker
{
    meta:
        description = "Blesh"
        author      = "Abhi"
        url         = "https://www.blesh.com/"

    strings:
        $code_signature    = /com\.blesh\.sdk\./
        $code_signature2   = /com\/blesh\/sdk\//

    condition:
        is_elf and any of them
}

rule bluecats : tracker
{
    meta:
        description = "Bluecats"
        author      = "Abhi"
        url         = "https://www.bluecats.com/"

    strings:
        $code_signature    = /com\.bluecats\.sdk/
        $code_signature2   = /com\/bluecats\/sdk/

    condition:
        is_elf and any of them
}

rule cooladata : tracker
{
    meta:
        description = "CoolaData"
        author      = "Abhi"
        url         = "https://www.cooladata.com/"

    strings:
        $code_signature    = /com\.cooladata\.android\./
        $code_signature2   = /com\/cooladata\/android\//

    condition:
        is_elf and any of them
}

rule fluzo : tracker
{
    meta:
        description = "FLUZO"
        author      = "Abhi"
        url         = "https://www.fluzo.com/"

    strings:
        $code_signature    = /com\.fluzo\.sdk\./
        $code_signature2   = /com\/fluzo\/sdk\//

    condition:
        is_elf and any of them
}

rule facebook_flipper : tracker
{
    meta:
        description = "FB. Flipper"
        author      = "Abhi"
        url         = "https://fbflipper.com"

    strings:
        $code_signature    = /com\.facebook\.flipper/
        $code_signature2   = /com\/facebook\/flipper/

    condition:
        is_elf and any of them
}

rule gpshopper : tracker
{
    meta:
        description = "GPShopper"
        author      = "Abhi"
        url         = "https://www.crunchbase.com/organization/gpshopper"

    strings:
        $code_signature    = /com\.gpshopper/
        $network_signature = /sdk\.gpshopper\.com|sypi\.gpshopper\.com/
        $code_signature2   = /com\/gpshopper/

    condition:
        is_elf and any of them
}

rule indooratlas : tracker
{
    meta:
        description = "IndoorAtlas"
        author      = "Abhi"
        url         = "http://www.indooratlas.com/"

    strings:
        $code_signature    = /com\.indooratlas\.android\.sdk/
        $network_signature = /ipsws\.indooratlas\.com/
        $code_signature2   = /com\/indooratlas\/android\/sdk/

    condition:
        is_elf and any of them
}

rule janrain : tracker
{
    meta:
        description = "Janrain"
        author      = "Abhi"
        url         = "https://en.wikipedia.org/wiki/Janrain"

    strings:
        $code_signature    = /com\.janrain\.android|com\.janrain\.android\.engage|com\.janrain\.android\.capture/
        $code_signature2   = /com\/janrain\/android|com\/janrain\/android\/engage|com\/janrain\/android\/capture/

    condition:
        is_elf and any of them
}

rule moca : tracker
{
    meta:
        description = "MOCA"
        author      = "Abhi"
        url         = "https://www.mocaplatform.com/"

    strings:
        $code_signature    = /com\.innoquant\.moca/
        $network_signature = /api-device\.mocaplatform\.com/
        $code_signature2   = /com\/innoquant\/moca/

    condition:
        is_elf and any of them
}

rule point_inside : tracker
{
    meta:
        description = "Point Inside"
        author      = "Abhi"
        url         = "https://www.pointinside.com/"

    strings:
        $code_signature    = /com\.pointinside/
        $code_signature2   = /com\/pointinside/

    condition:
        is_elf and any of them
}

rule proximi_io : tracker
{
    meta:
        description = "Proximi.io"
        author      = "Abhi"
        url         = "https://proximi.io/"

    strings:
        $code_signature    = /io\.proximi\.proximiiolibrary/
        $network_signature = /api\.proximi\.fi/
        $code_signature2   = /io\/proximi\/proximiiolibrary/

    condition:
        is_elf and any of them
}

rule scoreloop : tracker
{
    meta:
        description = "ScoreLoop"
        author      = "Abhi"
        url         = "https://www.scoreloop.com"

    strings:
        $code_signature    = /com\.scoreloop\.client\.android/
        $code_signature2   = /com\/scoreloop\/client\/android/

    condition:
        is_elf and any of them
}

rule alooma : tracker
{
    meta:
        description = "Alooma"
        author      = "Abhi"
        url         = "https://www.alooma.com"

    strings:
        $code_signature    = /com\.github\.aloomaio\.androidsdk/
        $network_signature = /inputs\.alooma\.com/
        $code_signature2   = /com\/github\/aloomaio\/androidsdk/

    condition:
        is_elf and any of them
}

rule analytics_by_npaw_youbora_suite : tracker
{
    meta:
        description = "Analytics by NPAW (Youbora Suite)"
        author      = "Abhi"
        url         = "https://nicepeopleatwork.com/"

    strings:
        $code_signature    = /com\.npaw\.youbora\./
        $code_signature2   = /com\/npaw\/youbora\//

    condition:
        is_elf and any of them
}

rule beintoo : tracker
{
    meta:
        description = "Beintoo"
        author      = "Abhi"
        url         = "https://beintoo.com/"

    strings:
        $code_signature    = /com\.beintoo\.nucleon/
        $code_signature2   = /com\/beintoo\/nucleon/

    condition:
        is_elf and any of them
}

rule bolts : tracker
{
    meta:
        description = "Bolts"
        author      = "Abhi"
        url         = "https://github.com/BoltsFramework/Bolts-Android"

    strings:
        $code_signature    = /com\.parse\.bolts/
        $code_signature2   = /com\/parse\/bolts/

    condition:
        is_elf and any of them
}

rule cedexis_radar : tracker
{
    meta:
        description = "Cedexis Radar"
        author      = "Abhi"
        url         = "https://www.cedexis.com/"

    strings:
        $code_signature    = /com\.cedexis/
        $network_signature = /cedexis\-radar\.net|cedexis\.com|radar\.cedexis\.com/
        $code_signature2   = /com\/cedexis/

    condition:
        is_elf and any of them
}

rule cifrasoft : tracker
{
    meta:
        description = "Cifrasoft"
        author      = "Abhi"
        url         = "http://cifrasoft.com"

    strings:
        $code_signature    = /com\.cifrasoft\./
        $network_signature = /\.tele\.fm/
        $code_signature2   = /com\/cifrasoft\//

    condition:
        is_elf and any of them
}

rule flowsense : tracker
{
    meta:
        description = "Flowsense"
        author      = "Abhi"
        url         = "https://flowsense.com.br/"

    strings:
        $code_signature    = /com\.flowsense\.flowsensesdk\./
        $code_signature2   = /com\/flowsense\/flowsensesdk\//

    condition:
        is_elf and any of them
}

rule geniee : tracker
{
    meta:
        description = "Geniee"
        author      = "Abhi"
        url         = "https://geniee.co.jp/"

    strings:
        $code_signature    = /jp\.co\.geniee\.gnadsdk\./
        $code_signature2   = /jp\/co\/geniee\/gnadsdk\//

    condition:
        is_elf and any of them
}

rule huq_sourcekit : tracker
{
    meta:
        description = "Huq Sourcekit"
        author      = "Abhi"
        url         = "https://huq.io/"

    strings:
        $code_signature    = /io\.huq\.sourcekit\./
        $code_signature2   = /io\/huq\/sourcekit\//

    condition:
        is_elf and any of them
}

rule insider : tracker
{
    meta:
        description = "Insider"
        author      = "Abhi"
        url         = "https://useinsider.com/"

    strings:
        $code_signature    = /com\.useinsider\.insider/
        $code_signature2   = /com\/useinsider\/insider/

    condition:
        is_elf and any of them
}

rule mopinion : tracker
{
    meta:
        description = "Mopinion"
        author      = "Abhi"
        url         = "https://mopinion.com"

    strings:
        $code_signature    = /com\.mopinion\.mopinionsdk/
        $code_signature2   = /com\/mopinion\/mopinionsdk/

    condition:
        is_elf and any of them
}

rule offertoro : tracker
{
    meta:
        description = "OfferToro"
        author      = "Abhi"
        url         = "http://www.offertoro.com/"

    strings:
        $code_signature    = /com\.offertoro\.sdk\./
        $code_signature2   = /com\/offertoro\/sdk\//

    condition:
        is_elf and any of them
}

rule opentelemetry_opencensus_opentracing : tracker
{
    meta:
        description = "OpenTelemetry (OpenCensus, OpenTracing)"
        author      = "Abhi"
        url         = "https://opentelemetry.io/"

    strings:
        $code_signature    = /io\.opencensus|io\.opentelemetry/
        $code_signature2   = /io\/opencensus|io\/opentelemetry/

    condition:
        is_elf and any of them
}

rule snapchat_login_kit : tracker
{
    meta:
        description = "Snapchat Login Kit"
        author      = "Abhi"
        url         = "https://kit.snapchat.com/docs/login-kit"

    strings:
        $code_signature    = /com\.snapchat\.kit\.sdk\.SnapLogin/
        $code_signature2   = /com\/snapchat\/kit\/sdk\/SnapLogin/

    condition:
        is_elf and any of them
}

rule zendrive : tracker
{
    meta:
        description = "Zendrive"
        author      = "Abhi"
        url         = "https://www.zendrive.com/"

    strings:
        $code_signature    = /com\.zendrive\.sdk\./
        $code_signature2   = /com\/zendrive\/sdk\//

    condition:
        is_elf and any of them
}

rule fullstory : tracker
{
    meta:
        description = "fullstory"
        author      = "Abhi"
        url         = "https://www.fullstory.com/"

    strings:
        $code_signature    = /com\.fullstory\.instrumentation\.|com\.fullstory\.util\.|com\.fullstory\.jni\.|com\.fullstory\.FS|com\.fullstory\.rust\.|com\.fullstory\.FSSessionData/
        $code_signature2   = /com\/fullstory\/instrumentation\/|com\/fullstory\/util\/|com\/fullstory\/jni\/|com\/fullstory\/FS|com\/fullstory\/rust\/|com\/fullstory\/FSSessionData/

    condition:
        is_elf and any of them
}

rule pendo : tracker
{
    meta:
        description = "Pendo"
        author      = "Abhi"
        url         = "https://www.pendo.io"

    strings:
        $code_signature    = /sdk\.insert\.io\.|sdk\.pendo\.io\./
        $code_signature2   = /sdk\/insert\/io\/|sdk\/pendo\/io\//

    condition:
        is_elf and any of them
}

rule plexure : tracker
{
    meta:
        description = "Plexure"
        author      = "Abhi"
        url         = "https://www.plexure.com/"

    strings:
        $code_signature    = /co\.vmob\.sdk/
        $code_signature2   = /co\/vmob\/sdk/

    condition:
        is_elf and any of them
}

rule swirl : tracker
{
    meta:
        description = "Swirl"
        author      = "Abhi"
        url         = "http://swirl.com/"

    strings:
        $code_signature    = /com\.swirl/
        $network_signature = /cdn-api\.swirl\.com/
        $code_signature2   = /com\/swirl/

    condition:
        is_elf and any of them
}

rule treasure_data : tracker
{
    meta:
        description = "Treasure Data"
        author      = "Abhi"
        url         = "https://www.treasuredata.com/product/"

    strings:
        $code_signature    = /com\.treasuredata/
        $code_signature2   = /com\/treasuredata/

    condition:
        is_elf and any of them
}

rule ibm_mobile_marketing_acoustic : tracker
{
    meta:
        description = "IBM Mobile Marketing (Acoustic)"
        author      = "Abhi"
        url         = "https://acoustic.co/"

    strings:
        $code_signature    = /com\.ibm\.mce\.sdk\.|co\.acoustic\.mobile\.push\.sdk\.|com\.xtify\.mce\.sdk\.|com\.xtify\.android\.sdk\./
        $network_signature = /sdk6\.ibm\.xtify\.com/
        $code_signature2   = /com\/ibm\/mce\/sdk\/|co\/acoustic\/mobile\/push\/sdk\/|com\/xtify\/mce\/sdk\/|com\/xtify\/android\/sdk\//

    condition:
        is_elf and any of them
}

rule solar_d_corona : tracker
{
    meta:
        description = "Solar2D (Corona)"
        author      = "Abhi"
        url         = "https://solar2d.com/"

    strings:
        $code_signature    = /com\.ansca\.corona/
        $code_signature2   = /com\/ansca\/corona/

    condition:
        is_elf and any of them
}

rule amazon_mobile_analytics_amplify : tracker
{
    meta:
        description = "Amazon Mobile Analytics (Amplify)"
        author      = "Abhi"
        url         = "https://aws.amazon.com/amplify/"

    strings:
        $code_signature    = /com\.amplifyframework\.analytics\./
        $code_signature2   = /com\/amplifyframework\/analytics\//

    condition:
        is_elf and any of them
}

rule ad_x : tracker
{
    meta:
        description = "AD(X)"
        author      = "Abhi"
        url         = "https://adxcorp.kr/"

    strings:
        $code_signature    = /com\.adxcorp\.ads|com\.adxcorp\.nativead/
        $code_signature2   = /com\/adxcorp\/ads|com\/adxcorp\/nativead/

    condition:
        is_elf and any of them
}

rule adgatemedia : tracker
{
    meta:
        description = "AdGateMedia"
        author      = "Abhi"
        url         = "https://adgatemedia.com/"

    strings:
        $code_signature    = /com\.adgatemedia\./
        $code_signature2   = /com\/adgatemedia\//

    condition:
        is_elf and any of them
}

rule admarvel : tracker
{
    meta:
        description = "AdMarvel"
        author      = "Abhi"
        url         = "https://www.crunchbase.com/organization/admarvel"

    strings:
        $code_signature    = /com\.admarvel\./
        $code_signature2   = /com\/admarvel\//

    condition:
        is_elf and any of them
}

rule adtiming : tracker
{
    meta:
        description = "AdTiming"
        author      = "Abhi"
        url         = "https://www.adtiming.com/"

    strings:
        $code_signature    = /com\.aiming\.mdt\.|com\.adtiming\./
        $code_signature2   = /com\/aiming\/mdt\/|com\/adtiming\//

    condition:
        is_elf and any of them
}

rule adjust_unbotify : tracker
{
    meta:
        description = "Adjust Unbotify"
        author      = "Abhi"
        url         = "https://www.adjust.com/product/unbotify/"

    strings:
        $code_signature    = /com\.unbotify\.mobile\.sdk\./
        $code_signature2   = /com\/unbotify\/mobile\/sdk\//

    condition:
        is_elf and any of them
}

rule lotadata : tracker
{
    meta:
        description = "LotaData"
        author      = "Abhi"
        url         = "http://lotadata.com"

    strings:
        $code_signature    = /com\.lotadata\.moments\./
        $code_signature2   = /com\/lotadata\/moments\//

    condition:
        is_elf and any of them
}

rule marketo_an_adobe_company : tracker
{
    meta:
        description = "Marketo (an Adobe Company)"
        author      = "Abhi"
        url         = "https://marketo.com"

    strings:
        $code_signature    = /com\.marketo\./
        $network_signature = /marketo\.com|marketo\.net|mktoedge\.com|mktossl\.com|\.mktorest\.com/
        $code_signature2   = /com\/marketo\//

    condition:
        is_elf and any of them
}

rule playtestcloud_event_tracking : tracker
{
    meta:
        description = "PlaytestCloud Event Tracking"
        author      = "Abhi"
        url         = "https://www.playtestcloud.com"

    strings:
        $code_signature    = /com\.playtestcloud\.Analytics/
        $code_signature2   = /com\/playtestcloud\/Analytics/

    condition:
        is_elf and any of them
}

rule rollbar : tracker
{
    meta:
        description = "Rollbar"
        author      = "Abhi"
        url         = "https://rollbar.com"

    strings:
        $code_signature    = /com\.rollbar\.android\./
        $code_signature2   = /com\/rollbar\/android\//

    condition:
        is_elf and any of them
}

rule snap_ad_kit : tracker
{
    meta:
        description = "Snap Ad Kit"
        author      = "Abhi"
        url         = "https://kit.snapchat.com/docs/ad-kit"

    strings:
        $code_signature    = /com\.snap\.adkit|com\.snap\.appadskit/
        $code_signature2   = /com\/snap\/adkit|com\/snap\/appadskit/

    condition:
        is_elf and any of them
}

rule synerise : tracker
{
    meta:
        description = "Synerise"
        author      = "Abhi"
        url         = "https://synerise.com"

    strings:
        $code_signature    = /com\.synerise\.sdk/
        $network_signature = /synerise\.com/
        $code_signature2   = /com\/synerise\/sdk/

    condition:
        is_elf and any of them
}

rule userexperior : tracker
{
    meta:
        description = "UserExperior"
        author      = "Abhi"
        url         = "https://www.userexperior.com/"

    strings:
        $code_signature    = /com\.userexperior/
        $code_signature2   = /com\/userexperior/

    condition:
        is_elf and any of them
}

rule vdopia : tracker
{
    meta:
        description = "Vdopia"
        author      = "Abhi"
        url         = "https://chocolateplatform.com/"

    strings:
        $code_signature    = /com\.vdopia\.client\.android\.|com\.vdopia\.ads\./
        $code_signature2   = /com\/vdopia\/client\/android\/|com\/vdopia\/ads\//

    condition:
        is_elf and any of them
}

rule adgem : tracker
{
    meta:
        description = "AdGem"
        author      = "Abhi"
        url         = "https://adgem.com/"

    strings:
        $code_signature    = /com\.adgem\.android\./
        $code_signature2   = /com\/adgem\/android\//

    condition:
        is_elf and any of them
}

rule adtrial : tracker
{
    meta:
        description = "AdTrial"
        author      = "Abhi"
        url         = "https://adtrial.com/"

    strings:
        $code_signature    = /com\.adtrial\.sdk\./
        $code_signature2   = /com\/adtrial\/sdk\//

    condition:
        is_elf and any of them
}

rule pincrux : tracker
{
    meta:
        description = "Pincrux"
        author      = "Abhi"
        url         = "https://www.pincrux.com/"

    strings:
        $code_signature    = /com\.pincrux\./
        $code_signature2   = /com\/pincrux\//

    condition:
        is_elf and any of them
}

rule tutucloud : tracker
{
    meta:
        description = "Tutucloud"
        author      = "Abhi"
        url         = "https://tutucloud.com"

    strings:
        $code_signature    = /org\.lasque\.tusdk\.core|org\.lasque\.tusdkpulse\.core/
        $network_signature = /tusdk\.com/
        $code_signature2   = /org\/lasque\/tusdk\/core|org\/lasque\/tusdkpulse\/core/

    condition:
        is_elf and any of them
}

rule veloxity : tracker
{
    meta:
        description = "Veloxity"
        author      = "Abhi"
        url         = "http://www.veloxity.net/"

    strings:
        $code_signature    = /net\.veloxity\./
        $code_signature2   = /net\/veloxity\//

    condition:
        is_elf and any of them
}

rule yoadx : tracker
{
    meta:
        description = "Yoadx"
        author      = "Abhi"
        url         = "https://yoadx.com/"

    strings:
        $code_signature    = /com\.yoadx\.yoadx\./
        $code_signature2   = /com\/yoadx\/yoadx\//

    condition:
        is_elf and any of them
}

rule coulus_coelib : tracker
{
    meta:
        description = "Coulus Coelib"
        author      = "Abhi"
        url         = "https://measurementsys.com/index.php#appdev"

    strings:
        $code_signature    = /coelib\.c\.couluslibrary/
        $code_signature2   = /coelib\/c\/couluslibrary/

    condition:
        is_elf and any of them
}

rule acra : tracker
{
    meta:
        description = "ACRA"
        author      = "Abhi"
        url         = "https://www.acra.ch/"

    strings:
        $code_signature    = /org\.acra\.|ch\.acra\./
        $code_signature2   = /org\/acra\/|ch\/acra\//

    condition:
        is_elf and any of them
}

rule backtrace : tracker
{
    meta:
        description = "Backtrace"
        author      = "Abhi"
        url         = "https://backtrace.io"

    strings:
        $code_signature    = /com\.github\.backtrace-labs\.|backtraceio\.library\./
        $network_signature = /backtrace\.io/
        $code_signature2   = /com\/github\/backtrace-labs\/|backtraceio\/library\//

    condition:
        is_elf and any of them
}

rule sentry : tracker
{
    meta:
        description = "Sentry"
        author      = "Abhi"
        url         = "https://sentry.io/"

    strings:
        $code_signature    = /io\.sentry\.|com\.joshdholtz\.sentry/
        $code_signature2   = /io\/sentry\/|com\/joshdholtz\/sentry/

    condition:
        is_elf and any of them
}

rule yueying_crash_sdk : tracker
{
    meta:
        description = "Yueying Crash SDK"
        author      = "Abhi"
        url         = "https://yueying-docs.effirst.com/"

    strings:
        $code_signature    = /com\.uc\.crashsdk|com\.uc2\.crashsdk/
        $code_signature2   = /com\/uc\/crashsdk|com\/uc2\/crashsdk/

    condition:
        is_elf and any of them
}
