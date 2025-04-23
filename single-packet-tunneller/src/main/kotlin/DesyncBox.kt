package burp

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*

class DesyncBox internal constructor() {

    companion object {
        lateinit var supportedPermutations: HashSet<String>

        //static final String PERMUTE_PREFIX = "permute: ";
        internal var sharedPermutations: SettingsBox = SettingsBox()
        internal var h1Permutations: SettingsBox = SettingsBox()
        internal var h2Permutations: SettingsBox = SettingsBox()

        internal var clPermutations: SettingsBox = SettingsBox()
        internal var sharedSettings: SettingsBox = SettingsBox()
        internal var h1Settings: SettingsBox = SettingsBox()
        internal var h2Settings: SettingsBox = SettingsBox()
    }

    init {
        // core techniques
        sharedPermutations.register("vanilla", true)
        sharedPermutations.register("underjoin1", false) // quite a few FP
        sharedPermutations.register("spacejoin1", true)
        sharedPermutations.register("space1", true)
        sharedPermutations.register("nameprefix1", true)
        sharedPermutations.register("nameprefix2", true)
        sharedPermutations.register("valueprefix1", true)
        sharedPermutations.register("vertwrap", true)
        sharedPermutations.register("0bprefix", true)
        sharedPermutations.register("connection", true)
        sharedPermutations.register("spjunk", true)
        sharedPermutations.register("backslash", true)
        sharedPermutations.register("spaceFF", true)
        sharedPermutations.register("unispace", true)
        sharedPermutations.register("commaCow", true)
        sharedPermutations.register("cowComma", true)
        sharedPermutations.register("contentEnc", true)
        sharedPermutations.register("quoted", true)
        sharedPermutations.register("aposed", true)
        sharedPermutations.register("dualchunk", true)
        sharedPermutations.register("lazygrep", true)
        sharedPermutations.register("0dsuffix", true)
        sharedPermutations.register("tabsuffix", true)
        sharedPermutations.register("revdualchunk", true)
        sharedPermutations.register("nested", true)
        sharedPermutations.register("encode", true)
        sharedPermutations.register("accentTE", true)
        sharedPermutations.register("accentCH", true)
        sharedPermutations.register("removed", true)
        sharedPermutations.register("get", true)
        sharedPermutations.register("options", true)
        sharedPermutations.register("head", true)
        sharedPermutations.register("range", true)


        for (i in specialChars) {
            sharedPermutations.register("spacefix1:$i", true)
        }

        for (i in specialChars) {
            sharedPermutations.register("prefix1:$i", true)
        }

        for (i in specialChars) {
            sharedPermutations.register("suffix1:$i", true)
        }

        for (i in specialChars) {
            sharedPermutations.register("namesuffix1:$i", true)
        }

        h1Permutations.register("nospace1", true)
        h1Permutations.register("linewrapped1", true)
        h1Permutations.register("gareth1", true)
        h1Permutations.register("badsetupCR", true)
        h1Permutations.register("badsetupLF", true)
        h1Permutations.register("multiCase", true)
        h1Permutations.register("tabwrap", true)
        h1Permutations.register("UPPERCASE", true)
        h1Permutations.register("0dwrap", true)
        h1Permutations.register("0dspam", true)
        h1Permutations.register("badwrap", true)
        h1Permutations.register("bodysplit", true)
        h1Permutations.register("h1case", true)
        h1Permutations.register("http1.0", true)

        h2Permutations.register("http2hide", true)
        h2Permutations.register("h2colon", true)
        h2Permutations.register("h2auth", true)
        h2Permutations.register("h2path", true)
        h2Permutations.register("http2case", true)
        h2Permutations.register("h2scheme", true)
        h2Permutations.register("h2name", true)
        h2Permutations.register("h2method", true)
        h2Permutations.register("h2space", true)
        h2Permutations.register("h2prefix", true)
        h2Permutations.register("h2CL", true)

        clPermutations.register("CL-plus", true)
        clPermutations.register("CL-minus", true)
        clPermutations.register("CL-pad", true)
        clPermutations.register("CL-bigpad", true)
        clPermutations.register("CL-e", true)
        clPermutations.register("CL-dec", true)
        clPermutations.register("CL-commaprefix", true)
        clPermutations.register("CL-commasuffix", true)
        clPermutations.register("CL-expect", true)
        clPermutations.register("CL-error", true)
        clPermutations.register("CL-spacepad", true)

        supportedPermutations = HashSet()
        supportedPermutations.addAll(sharedPermutations.settings)
        supportedPermutations.addAll(h1Permutations.settings)
        supportedPermutations.addAll(h2Permutations.settings)
        supportedPermutations.addAll(clPermutations.settings)

    }

    fun applyDesync(request: ByteArray, header: String, technique: String): ByteArray? {
        var request = request
        var header = header
        val headerValue = Utilities.getHeader(request, header)
        header = "$header: "
        var value = ""
        value = if (header == ("Content-Length: ")) {
            Utilities.getHeader(request, "Content-Length")
        } else if (header == "Transfer-Encoding: ") {
            "chunked"
        } else {
            throw RuntimeException("Unsupported target header: $header")
        }

        var permuted: String? = null
        var transformed = request


        when (technique) {
            "underjoin1" -> permuted = header.replace("-", "_")
            "spacejoin1" -> permuted = header.replace("-", " ")
            "space1" -> permuted = header.replace(":", " :")
            "nameprefix1" -> permuted = "Foo: bar\r\n $header"
            "nameprefix2" -> permuted = "Foo: bar\r\n\t$header"
            "valueprefix1" -> permuted = "$header "
            "nospace1" -> permuted = header.replace(" ", "")
            "linewrapped1" -> permuted = header.replace(" ", "\n ")
            "gareth1" -> permuted = header.replace(":", "\n :")
            "badsetupCR" -> permuted = "Foo: bar\r$header"
            "badsetupLF" -> permuted = "Foo: bar\n$header"
            "vertwrap" -> permuted = header + "\n\u000B"
            "0bprefix" -> permuted = header.replace(" ", "\u000B")
            "tabwrap" -> permuted = header + "\r\n\t"
            "multiCase" -> {
                permuted = header.uppercase(Locale.getDefault())
                permuted = permuted.substring(0, 1).lowercase(Locale.getDefault()) + permuted.substring(1)
            }

            "UPPERCASE" -> permuted = header.uppercase(Locale.getDefault())
            "0dwrap" -> permuted = "Foo: bar\r\n\r$header"
            "0dspam" -> permuted = header.substring(0, 3) + "\r" + header.substring(3)
            "connection" -> permuted =
                """
 Connection: ${header.split(": ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()[0]}
 $header
 """.trimIndent()

            "spjunk" ->                 // Technique from "HTTP Request Smuggling in 2020"  by Amit Klein
                permuted = header.replace(":", " x:")

            "backslash" ->                 // Technique from "HTTP Request Smuggling in 2020"  by Amit Klein
                permuted = header.replace("-", "\\")
        }


        for (i in specialChars) {
            if (technique == "spacefix1:$i") {
                permuted = header.replace(" ", "") + i.toChar()
            }
        }

        for (i in specialChars) {
            if (technique == "prefix1:$i") {
                permuted = header + i.toChar()
            }
        }

        for (i in specialChars) {
            if (technique == "namesuffix1:$i") {
                permuted = header.replace(":", i.toChar().toString() + ":")
            }
        }

        if (permuted != null) {
            transformed = Utilities.replace(request, header, permuted)
        }

        if (technique == "badwrap") {
            transformed = Utilities.replace(request, header, "X-Blah-Ignore: ")
            transformed = Utilities.replaceFirst(transformed, "\r\n", "\r\n $header$headerValue\r\n")
        }

        if (technique == "spaceFF") {
            try {
                val encoded = ByteArrayOutputStream()
                encoded.write(header.substring(0, header.length - 1).toByteArray())
                encoded.write(0xFF.toByte().toInt())
                transformed = Utilities.replace(request, header.toByteArray(), encoded.toByteArray())
            } catch (e: IOException) {
            }
        }
        if (technique == "unispace") {
            try {
                val encoded = ByteArrayOutputStream()
                encoded.write(header.substring(0, header.length - 1).toByteArray())
                encoded.write(0xa0.toByte().toInt())
                transformed = Utilities.replace(request, header.toByteArray(), encoded.toByteArray())
            } catch (e: IOException) {
            }
        }

        if (technique == "http1.0") {
            transformed = Utilities.replaceFirst(transformed, "HTTP/1.1", "HTTP/1.0")
        }

        when (technique) {
            "0dsuffix" -> transformed = Utilities.replace(request, header + value, header + value + "\r")
            "tabsuffix" -> transformed = Utilities.replace(request, header + value, header + value + "\t")
            "h2auth" -> transformed = Utilities.replace(
                request,
                header + value,
                ":authority: " + Utilities.getHeader(request, "Host") + ":443^~" + header + value + "^~x: x"
            )

            "h2path" -> transformed = Utilities.replace(
                request,
                header + value,
                ":path: " + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x"
            )

            "h2scheme" -> transformed = Utilities.replace(
                request,
                header + value,
                ":scheme: https://" + Utilities.getHeader(
                    request,
                    "Host"
                ) + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x"
            )

            "h2method" -> transformed = Utilities.replace(
                request,
                header + value,
                ":method: POST " + Utilities.getPathFromRequest(request) + " HTTP/1.1^~" + header + value + "^~x: x"
            )

            "removed" -> transformed = Utilities.replace(request, header + value, "Nothing-interesting: 1")
            "get" -> transformed = Utilities.setMethod(request, "GET")
            "options" -> transformed = Utilities.setMethod(request, "OPTIONS")
            "head" -> transformed = Utilities.setMethod(request, "HEAD")
            "range" -> transformed = Utilities.addOrReplaceHeader(request, "Range", "bytes=0-0")
            "h2CL" -> {
                transformed = Utilities.setHeader(request, "Content-Length", "0")
                // we have to bypass the no-effect check
                return transformed
            }
        }

        for (i in specialChars) {
            if (technique == "suffix1:$i") {
                transformed = Utilities.replace(
                    request,
                    (header + value).toByteArray(),
                    (header + value + i.toChar()).toByteArray()
                )
            }
        }

        if (header == "Transfer-Encoding: ") {
            if (technique == "commaCow") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked".toByteArray(),
                    "Transfer-Encoding: chunked, identity".toByteArray()
                )
            } else if (technique == "cowComma") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: ".toByteArray(),
                    "Transfer-Encoding: identity, ".toByteArray()
                )
            } else if (technique == "contentEnc") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: ".toByteArray(),
                    "Content-Encoding: ".toByteArray()
                )
            } else if (technique == "quoted") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked".toByteArray(),
                    "Transfer-Encoding: \"chunked\"".toByteArray()
                )
            } else if (technique == "aposed") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked".toByteArray(),
                    "Transfer-Encoding: 'chunked'".toByteArray()
                )
            } else if (technique == "dualchunk") {
                transformed = Utilities.addOrReplaceHeader(request, "Transfer-encoding", "identity")
            } else if (technique == "lazygrep") {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding: chunk")
            } else if (technique == "revdualchunk") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked",
                    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked"
                )
            } else if (technique == "bodysplit") {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "X: y")
                transformed = Utilities.addOrReplaceHeader(transformed, "Foo", "barzxaazz")
                transformed = Utilities.replace(transformed, "barzxaazz", "barn\n\nTransfer-Encoding: chunked")
            } else if (technique == "nested") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked",
                    "Transfer-Encoding: identity, chunked, identity"
                )
            } else if (technique == "http2hide") {
                transformed = Utilities.replace(
                    request,
                    "Transfer-Encoding: chunked",
                    "Foo: b^~Transfer-Encoding: chunked^~x: x"
                )
            } else if (technique == "encode") {
                transformed =
                    Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-%45ncoding: chunked")
            } else if (technique == "h2colon") {
                transformed = Utilities.replace(request, "Transfer-Encoding: chunked", "Transfer-Encoding`chunked : chunked")
            } else if (technique == "http2case") {
                request = (String(request)).lowercase(Locale.getDefault()).toByteArray()
                transformed =
                    Utilities.replace(request, header + value, "x-reject: 1\r\ntransfer-Encoding: chunked")
            } else if (technique == "h2name") {
                transformed = Utilities.replace(request, header + value, "Transfer-Encoding`chunked^~xz: x")
            } else if (technique == "h2space") {
                transformed = Utilities.replace(request, header + value, "Transfer-Encoding chunked : chunked")
            } else if (technique == "h1case") {
                transformed =
                    Utilities.replace(request, header + value, header.uppercase(Locale.getDefault()) + value)
            } else if (technique == "h2prefix") {
                transformed = Utilities.replace(request, header + value, ":transfer-encoding: chunked")
            }

            if (technique == "accentTE") {
                try {
                    val encoded = ByteArrayOutputStream()
                    encoded.write("Transf".toByteArray())
                    encoded.write(0x82.toByte().toInt())
                    encoded.write("r-Encoding: ".toByteArray())
                    transformed = Utilities.replace(request, header.toByteArray(), encoded.toByteArray())
                } catch (e: IOException) {
                }
            }
            if (technique == "accentCH") {
                try {
                    val encoded = ByteArrayOutputStream()
                    encoded.write("Transfer-Encoding: ch".toByteArray())
                    encoded.write(0x96.toByte().toInt())
                    transformed =
                        Utilities.replace(request, "Transfer-Encoding: chu".toByteArray(), encoded.toByteArray())
                } catch (e: IOException) {
                }
            }
        }

        if (header == ("Content-Length: ")) {
            when (technique) {
                "CL-plus" -> transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: +")
                "CL-minus" -> transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: -")
                "CL-pad" -> transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 0")
                "CL-bigpad" -> transformed =
                    Utilities.replace(request, "Content-Length: ", "Content-Length: 00000000000")

                "CL-spacepad" -> transformed = Utilities.replace(request, "Content-Length: ", "Content-Length: 0 ")
                "CL-e" -> transformed =
                    Utilities.replace(request, "Content-Length: $value", "Content-Length: " + value + "e0")

                "CL-dec" -> transformed = Utilities.replace(
                    request, "Content-Length: $value",
                    "Content-Length: $value.0"
                )

                "CL-commaprefix" -> transformed =
                    Utilities.replace(request, "Content-Length: ", "Content-Length: 0, ")

                "CL-commasuffix" -> transformed = Utilities.replace(
                    request, "Content-Length: $value",
                    "Content-Length: $value, 0"
                )

                "CL-expect" -> transformed = Utilities.addOrReplaceHeader(request, "Expect", "100-continue")
                "CL-error" -> transformed = Utilities.replace(
                    request, "Content-Length: $value",
                    "X-Invalid Y: \r\nContent-Length: $value"
                )
            }
        }

        if (transformed.contentEquals(request) && technique != "vanilla") {
            if (header == "Content-Length: ") {
                return null
            }
            Utilities.err("Requested desync technique had no effect: $technique")
        }

        return transformed
    }

    val specialChars: ArrayList<Int>
        get() {
            val chars = ArrayList<Int>()

            //        for (int i=0;i<32;i++) {
            //            chars.add(i);
            //        }
            chars.add(0) // null
            chars.add(9) // tab
            chars.add(11) // vert tab
            chars.add(12) // form feed
            chars.add(13) // \r
            chars.add(127)
            return chars
        }
}