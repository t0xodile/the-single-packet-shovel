package burp

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import java.io.FileNotFoundException
import kotlin.math.roundToInt

//this is a basic scan check implementation
internal class TunnelHeaderGuess(name: String?) : Scan(name) {

    // Declare instance properties for the settings
    private var singlePacketGroupSize: Int = 0
    private var singlePacketRetryMax: Int = 0
    private var skipBoringHeaders: Boolean = false
    private var headerBucketDivisor: Int = 0

    //Init is a constructor in Kotlin. Import any settings you wanted outside the global ones
    init {
        super.name
        scanSettings.importSettings(BurpExtender.configSettings)
        scanSettings.register("Single-packet group size", 5, "How many requests should be in each single-packet attack.")
        scanSettings.register("Single-packet retry max", 100, "Number of times to retry the single-packet attack before giving up.")
        scanSettings.register("Skip boring headers", true, "Skip headers in the boring list.")
        scanSettings.register("Initial Header Bucket Divisor", 256, "How many sets to split the header list into.")
    }

    //this is where your scan logic goes
    override fun doScan(baseReq: ByteArray, service: IHttpService): MutableList<IScanIssue> {
        singlePacketGroupSize = Utilities.globalSettings.getInt("Single-packet group size")
        singlePacketRetryMax = Utilities.globalSettings.getInt("Single-packet retry max")
        skipBoringHeaders = Utilities.globalSettings.getBoolean("Skip boring headers")
        headerBucketDivisor = Utilities.globalSettings.getInt("Initial Header Bucket Divisor")

        val cacheBustedBaseReq = Utilities.addCacheBuster(baseReq, Utilities.generateCanary()) //Important to add a cache buster here....

        val baseRequest = Utilities.buildMontoyaReq(cacheBustedBaseReq, service) //Easy way to build a montoya request so you can stop messing with the old version

        //Grab base response which should be tunnelled
        val (baseNestedResponse, baseRequestResponse) = attemptTunnel(baseRequest)

        //If we failed.... exit
        if (baseNestedResponse == null) {
            return mutableListOf<IScanIssue>()
        }

        //Grab headers and split into 4 lists initially
        var headersList = this::class.java.getResourceAsStream("/headers.txt")?.bufferedReader()?.readLines()?: throw FileNotFoundException("Resource headers.txt not found")
        headersList = headersList.toMutableList()


        //remove the boring headers from the header list if enabled
        if (Utilities.globalSettings.getBoolean("Skip boring headers")) {
            val boringHeaders = this::class.java.getResourceAsStream("/boringHeaders.txt")?.bufferedReader()?.readLines()?: throw FileNotFoundException("Resource headers.txt not found")
            for (boringHeader in boringHeaders) {
                if (boringHeader in headersList) {
                    headersList.remove(boringHeader)
                }
            }
        }

        //Remove invalid chars from headers
        headersList.forEachIndexed { index, header ->
            headersList[index] = header.replace("[^a-z0-9_-]".toRegex(), "")
        }

        // The above results in some empty headers and we don't want those.
        headersList.removeIf { it.isEmpty() }

        //Find out how many headers we can guess at once...
        var bucketSizeTooLarge: Boolean = true

        while (bucketSizeTooLarge) {
            if (Utilities.unloaded.get()) {
                break
            }

            val headers = headersList.chunked(headersList.size / headerBucketDivisor)

            val checkRequest = buildTunnelRequestWithHeaders(baseRequest, headers[0])
            val (tunnelledResponse, tunnelRequestResponse) = attemptTunnel(checkRequest)

            if (tunnelledResponse == null) {
                return mutableListOf<IScanIssue>()
            }

            if (tunnelledResponse.statusCode() == 431.toShort()) {
                Utilities.out("Reducing header bucket size due to a 431 response.")
                headerBucketDivisor = (headerBucketDivisor * 1.5).roundToInt()
            } else {
                bucketSizeTooLarge = false
            }
        }

        var interestingHeader: String? = null

        do {
            //remove the last header we found and look for more!
            if (interestingHeader != null) {
                headersList.remove(interestingHeader)
            }

            val sets = headersList.chunked(headersList.size / headerBucketDivisor)

            //Add all the headers to the check request
            val setWithInterestingHeader: List<String>? = findSetWithInterestingHeader(baseRequest, baseNestedResponse, sets)

            //Return early if none of the sets contained an interesting header
            if (setWithInterestingHeader == null) {
                return mutableListOf<IScanIssue>()
            }

            //Binary search for the header that actually did the thing....
            val (result, newInterestingHeader) = binarySearchForInterestingHeader(baseRequest, baseNestedResponse, setWithInterestingHeader)
            interestingHeader = newInterestingHeader

            if (result != null) {
                report("Tunnelled Header Found: $interestingHeader", "Super sneaky header found", baseRequestResponse, result)
            }

        } while (interestingHeader != null)

        return mutableListOf<IScanIssue>()
    }

    private fun attemptTunnel(request: HttpRequest): Pair<HttpResponse?, HttpRequestResponse?> {
        for (attempt in 1..singlePacketRetryMax) {
            if (Utilities.unloaded.get()) {
                break
            }

            val raceGroup = listOf<HttpRequest>().toMutableList()
            for (i in 1..singlePacketGroupSize) {
                raceGroup.add(request)
            }

            val requestResponses = Utilities.montoyaApi.http().sendRequests(raceGroup)

            for (requestResponse in requestResponses) {
                val h1InResponseBody = Regex("HTTP/1[.][01] [0-9]")

                // Skip over any empty responses....
                if (!requestResponse.hasResponse()) {
                    continue
                }

                if (h1InResponseBody.containsMatchIn(requestResponse.response().toString())) {
                    val nestedResponse = HttpResponse.httpResponse(getNestedResponse(requestResponse.response()))

                    val tunnelledRequestResponse = requestResponse //Store this incase we want to report on it
                    return Pair(nestedResponse, tunnelledRequestResponse)
                }
            }
        }
        Utilities.out("Failed to tunnel request after $singlePacketRetryMax attempts... Exiting.")
        return Pair(null, null)
    }

    private fun findSetWithInterestingHeader(request: HttpRequest, baseNestedResponse:HttpResponse, sets: List<List<String>>): List<String>? {
        for (set in sets) {
            val checkRequest = buildTunnelRequestWithHeaders(request, set)

            val (tunnelSuccess, tunnelRequestResponse) = attemptTunnel(checkRequest)

            if (tunnelSuccess == null) {
                return listOf()
            }

            //Analyze the responses to see if they match at all
            if (!similar(baseNestedResponse, tunnelSuccess)) {
                return set
            }
        }
        return null
    }

    private fun binarySearchForInterestingHeader(request: HttpRequest, baseNestedResponse: HttpResponse, set: List<String>): Pair<HttpRequestResponse?, String?> {
        var min = 0
        var max = set.size -1

        var result: HttpRequestResponse? = null
        var interestingHeader: String? = null

        while (min <= max) {
            if (Utilities.unloaded.get()) {
                break
            }
            val guess = min + (max - min) / 2
            //Utilities.err("Min: $min, Max: $max, Guess: $guess")
            val headersToCheck = set.slice(min..guess)

            var checkRequest = request.withBody(request.bodyToString().slice(0 until request.bodyToString().lastIndexOf("\r\n\r\n"))) //Reset the checkRequest for the next set of headers
            var nestedRequestHeaders = ""
            for (header in headersToCheck) {
                nestedRequestHeaders += "\r\n$header: ${Utilities.generateCanary()}"
            }

            val newBody = checkRequest.bodyToString() + nestedRequestHeaders + "\r\n\r\n"
            checkRequest = checkRequest.withBody(newBody)

            val (tunnelSuccess, tunnelRequestResponse) = attemptTunnel(checkRequest)

            if (tunnelSuccess == null) {
                return Pair(null, null)
            }

            //If we find no difference, then we need to go to the other side of the current list
            if (similar(baseNestedResponse, tunnelSuccess)) {
                //Don't store the result because they were similar....
                result = null

                if (headersToCheck.size == 1) {
                    interestingHeader = headersToCheck[0]
                }

                min = guess + 1
            } else { // If there is a difference, then we were in the right place, so we can get rid of the other half of the current list
                result = tunnelRequestResponse

                if (headersToCheck.size == 1) {
                    interestingHeader = headersToCheck[0]
                }

                max = guess - 1
            }
        }

        return Pair(result, interestingHeader)
    }

    private fun buildTunnelRequestWithHeaders(request: HttpRequest, headers: List<String>): HttpRequest {
        var checkRequest = request.withBody(request.bodyToString().slice(0 until request.bodyToString().lastIndexOf("\r\n\r\n")))
        var nestedRequestHeaders = ""
        for (header in headers) {
            nestedRequestHeaders += "\r\n${header}: ${Utilities.generateCanary()}"
        }

        val newBody = checkRequest.bodyToString() + nestedRequestHeaders + "\r\n\r\n"
        checkRequest = checkRequest.withBody(newBody)

        return checkRequest
    }
}

fun similar(baseResponse: HttpResponse, compareResponse: HttpResponse): Boolean {
    //Generate a key and use it to compare....
    val baseKey = "${baseResponse.statusCode()}${baseResponse.headerValue("content-type")}${baseResponse.headerValue("server")}"
    val compKey = "${compareResponse.statusCode()}${compareResponse.headerValue("content-type")}${compareResponse.headerValue("server")}"

    //Are the requests similar in key. I.e. 200Text/HtmlApacheTomcat vs 500Text/HtmlNginx
    if (baseKey != compKey) {
        return false
    }

    //Assuming the requests are similar enough based on key, do they differ given our list of keywords
    if (getKeywords(baseResponse, compareResponse).isNotEmpty()) {
        return false
    }

    //Assuming the list of keywords that differs is empty, then they must not differ at all / enough to report
    return true
}

fun getKeywords(baseResponse: HttpResponse, compareResponse: HttpResponse): MutableSet<String> {
    val keywords: List<String> = listOf("\",\"", "true", "false", "\"\"", "[]", "</html>", "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor", "divide", "ora-", "division", "infinity", "<script", "<div")
    val keywordAnalyzer = Utilities.montoyaApi.http().createResponseKeywordsAnalyzer(keywords)
    keywordAnalyzer.updateWith(baseResponse)
    keywordAnalyzer.updateWith(compareResponse)
    val keywordResults = keywordAnalyzer.variantKeywords()

    return keywordResults
}

fun getNestedResponse(response: HttpResponse): String? {
    val body = response.body().toString()
    val h1InResponseBody = Regex("HTTP/1[.][01] [0-9]")

    if (!h1InResponseBody.containsMatchIn(body)) {
        return null
    }

    val nestedResponseStart = body.indexOf("HTTP/1", 0, true)
    val nestedResponse = body.slice(nestedResponseStart..<body.length)
    return nestedResponse
}