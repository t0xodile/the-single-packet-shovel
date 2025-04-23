package burp

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import java.util.*

//this is a basic scan check implementation
internal class SPCLTunnelScan(name: String?) : Scan(name) {

    // Declare instance properties for the settings
    private var singlePacketGroupSize: Int = 0
    val desyncBox = DesyncBox()

    //Init is a constructor in Kotlin. Import any settings you wanted outside the global ones
    init {
        super.name
        scanSettings.importSettings(BurpExtender.configSettings)
        scanSettings.importSettings(DesyncBox.h2Permutations)
        scanSettings.importSettings(DesyncBox.h1Permutations)
        scanSettings.importSettings(DesyncBox.sharedSettings)
        scanSettings.importSettings(DesyncBox.sharedPermutations)
        scanSettings.importSettings(DesyncBox.clPermutations)
        scanSettings.register("Single-packet group size", 5, "How many requests should be in each single-packet attack.")
        scanSettings.register("convert GET to POST", true)

    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {

        // Return early if not HTTP2
        if (!Utilities.isHTTP2(baseReq)) {
            return mutableListOf<IScanIssue>()
        }

        val enabledPermutations = arrayListOf<String>()
        for (permutation in DesyncBox.supportedPermutations) {
            if (scanSettings.contains(permutation)) {
                if (Utilities.globalSettings.getBoolean(permutation)) {
                    enabledPermutations.add(permutation)
                }
            }
        }

        singlePacketGroupSize = Utilities.globalSettings.getInt("Single-packet group size")

        //Loop through all enabled permutations and queue up each attack
        var baseReqWithPermutation:ByteArray? = baseReq

        for (permutation in enabledPermutations) {
            if (Utilities.unloaded.get()) {
                break
            }

            var baseReqWithSmuggleHeaders = Utilities.addCacheBuster(baseReq, Utilities.generateCanary()) // cache buster is important.
            baseReqWithSmuggleHeaders = Utilities.addOrReplaceHeader(baseReqWithSmuggleHeaders, "Content-Length", "7")

            baseReqWithPermutation = desyncBox.applyDesync(baseReqWithSmuggleHeaders, "Content-Length", permutation)

            //Skip current perm if we couldn't actually apply the permutation
            if (baseReqWithPermutation == null) {
                continue
            }

            //If swap method to POST if enabled
            if (Utilities.globalSettings.getBoolean("convert GET to POST")) {
                baseReqWithPermutation = Utilities.helpers.toggleRequestMethod(baseReqWithPermutation)
            }

            baseReqWithPermutation = Utilities.setBody(baseReqWithPermutation, "FOO\r\n\r\n")

            val checkResponses = h2SinglePacketRequest(service, baseReqWithPermutation, transform = true)


            if (checkResponses == null) {
                continue
            }

            for (requestResponse in checkResponses) {
                if (requestResponse.response() == null) {
                    continue
                }
                if (requestResponse.response().body() == null) {
                    continue
                }

                val h1InResponseBody = Regex("HTTP/1[.][01] [0-9]")

                if (h1InResponseBody.containsMatchIn(requestResponse.response().bodyToString())) {
                    report(
                        "H2.SP.CL Request Tunnelling - $permutation",
                        "The attached request was sent $singlePacketGroupSize times in a single-packet attack which resulted in request tunnelling.",
                        requestResponse
                    )
                    break
                }
            }
        }

        return mutableListOf()
    }

    private fun h2SinglePacketRequest(service: IHttpService, req: ByteArray?, transform: Boolean): MutableList<HttpRequestResponse>? {
        if (Utilities.unloaded.get()) {
            throw RuntimeException("Aborting request due to extension unload")
        }

        val h2headers: LinkedList<Pair<String, String>> = H2Connection.Companion.buildReq(HTTP2Request(Utilities.helpers.bytesToString(req)), transform)
        val headers = mutableListOf<HttpHeader>()
        for (h2header in h2headers) {
            headers.add(HttpHeader.httpHeader(h2header.first, h2header.second))
        }

        //Correct service type
        val montoyaService = HttpService.httpService("${service.protocol}://${service.host}:${service.port}")

        val body = Utilities.getBody(req)
        //var responseBytes: ByteArray?
        var requestResponses: MutableList<HttpRequestResponse>?
        Utilities.requestCount.incrementAndGet()
        val startTime = System.currentTimeMillis()

        val montoyaRequest = HttpRequest.http2Request(montoyaService, headers, body)

        val raceGroup = mutableListOf<HttpRequest>()

        for (i in 1..Utilities.globalSettings.getInt("Single-packet group size")) {
            raceGroup.add(montoyaRequest)
        }

        try {
            //responseBytes = Utilities.callbacks.makeHttp2Request(service, headers, body, true)
            requestResponses = Utilities.montoyaApi.http().sendRequests(raceGroup)
        } catch (e: NoSuchMethodError) {
            Utilities.out("To enable HTTP/2-specific attacks, you need to use Burp Suite 2020.8 or later")
            requestResponses = null
        } catch (e: RuntimeException) {
            Utilities.out(e.message)
            requestResponses = null
        }
        return requestResponses
    }
}
