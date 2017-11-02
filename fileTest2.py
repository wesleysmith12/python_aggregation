import sys
from datetime import datetime
import time 
import calendar
from collections import Counter

#routers and reserved addresses
#_0000 = 0
#_BBB1 = 0
#_D7B2 = 0
#_36CF = 0
#_FFFF = 0
##south conference room
#_8D38 = 0
#_469A = 0
#_E86C = 0
#_0CD0 = 0
##game room
#_28DE = 0
#_8F8C = 0
#_AB52 = 0
#_9A17 = 0
##office conference
#_713B = 0
#_919F = 0
##office
#_56A8 = 0
#_CF87 = 0
#_3CFD = 0
#_7B46 = 0
##Kyle's office
#_AF65 = 0
#_D7B1 = 0
#_27A8 = 0
##unknown
#_0870 = 0
#_6541 = 0

#get block size from args
time = int(sys.argv[1])

#open sniffer file to read from
fr = open("refinedPackets11_18.txt", "r")
#create file to write to
fo = open("agregated.txt", "w")

#read timestamp of first packet
filedata = fr.read(51)[0:19]; #change to 26 to include miliseconds

#convert timestamp to seconds
initStripped = datetime.strptime(filedata, "%Y-%m-%dT%H:%M:%S") #.%f
initSeconds = calendar.timegm(initStripped.utctimetuple())
#dateStripped = datetime.strptime(line[0:19], "%Y-%m-%dT%H:%M:%S")

nextStart = False
blockStarted = False
#keep track of line in file
index = 0
#where to revert back to after block is finished
revertIndex = 0

startTime = " "
totalLength = 0
maxLength = 2
minLength = 1000
totalPackets = 0
srcAddress = " "
destAddress = " "
lineNumber = 1
revertLineNumber = 0
nextBlockInitSecods = 0
rowIndex = 0
startTimeStamp = 'none'

#how many lines are in the file
totalLines = 0
with open('refinedPackets11_18.txt', 'r') as f:
	for line in f:
		totalLines += 1

#aggregate file
with open('refinedPackets11_18.txt', 'r') as f:
	for line in f:
		
		#print("source Address", destAddress)
			
		dateStripped = datetime.strptime(line[0:19], "%Y-%m-%dT%H:%M:%S")
		timeInSeconds = calendar.timegm(dateStripped.utctimetuple())
		#print("seconds: ",timeInSeconds)

		#check to see if block has ended
		if timeInSeconds >= (initSeconds + time):

			fo.write(startTimeStamp + ' ' + str(startTime) + ' ' + str(totalLength) + ' ' + str(maxLength) + ' ' + str(minLength) + ' ' + str(totalPackets) + ' ' + str(countSrc['af65']) + ' ' + str(countSrc['d7b1']) + ' ' + str(countSrc['27a8']) + ' ' + str(countSrc['0000']) + ' ' + str(countSrc['bbb1']) + ' ' + str(countSrc['d7b2']) + ' ' + str(countSrc['36cf']) + ' ' + str(countSrc['8d38']) + ' ' + str(countSrc['469a']) + ' ' + str(countSrc['e86c']) + ' ' + str(countSrc['0cd0']) + ' ' + str(countSrc['28de']) + ' ' + str(countSrc['8f8c']) + ' ' + str(countSrc['ab52']) + ' ' + str(countSrc['9a17']) + ' ' + str(countSrc['71b3']) + ' ' + str(countSrc['919f']) + ' ' + str(countSrc['56a8']) + ' ' + str(countSrc['cf87']) + ' ' + str(countSrc['3cfd']) + ' ' + str(countSrc['7b46']) + ' ' + str(countSrc['0870']) + ' ' + str(countSrc['6541']) + ' ');

#"D7B1" + "27A8"
			
			fo.write(str(countDest['af65']) + ' ' +  str(countDest['d7b1']) + ' ' + str(countDest['27a8']) + ' ' + str(countDest['0000']) + ' ' + str(countDest['bbb1']) + ' ' + str(countDest['d7b2']) + ' ' + str(countDest['36cf']) + ' ' + str(countDest['8d38']) + ' ' + str(countDest['469a']) + ' ' + str(countDest['e86c']) + ' ' + str(countDest['0cd0']) + ' ' + str(countDest['28de']) + ' ' + str(countDest['8f8c']) + ' ' + str(countDest['ab52']) + ' ' + str(countDest['9a17']) + ' ' + str(countDest['71b3']) + ' ' + str(countDest['919f']) + ' ' + str(countDest['56a8']) + ' ' + str(countDest['cf87']) + ' ' + str(countDest['3cfd']) + ' ' + str(countDest['7b46']) + ' ' + str(countDest['0870']) + ' ' + str(countDest['6541']) + '\n');

			#reset variables
			totalLength = 0
			maxLength = 0
			minLength = 1000
			totalPackets = 0
			startTime = " "

			#reset counters
			del countSrc
			del countDest
		
			blockStarted = False
			initSeconds = timeInSeconds

			#start counting addresses
		if not blockStarted:
			
			#print("block started")
				
			#print("counter started")
			countSrc = Counter()
			countDest = Counter()
			blockStarted = True
			
			rowIndex+=1
			lineNumber+=1
			index+=len(line)
			#testing
			#fo.write(line);		
		if maxLength < int(line[20:23]):
			maxLength = int(line[20:23])
		if minLength > int(line[20:23]):
			minLength = int(line[20:23])
		totalPackets += 1
		srcAddress = line[33:37]
			#print("Source: ", srcAddress)

			#add source address to counts for current block
		countSrc[srcAddress] += 1

		totalLength += int(line[20:23])	
		if startTime == " ":
			startTime = int(line[11:13])/3
			startTimeStamp = line[:19]
			#test time groups
			#print("Hour: " + line[11:13] + " Group: " + str(startTime))

			#startTime = line[0:19] #get hour and mod by a certain number of hours
		destAddress = line[40:44]

		#add dest address to counts for current block
		#countDest += Counter([destAddress])
		countDest[destAddress] += 1

			#print(str(timeInSeconds))

			#print off last data before exiting loop
		if lineNumber == totalLines+1:
			#fo.write(str(startTime) + ' ' + str(totalLength) + ' ' + str(maxLength) + ' ' + str(minLength) + ' ' + str(totalPackets) + ' ' + str(_0000) + ' ' + str(_BBB1) + ' ' + str(_D7B2) + ' ' + str(_36CF) + ' ' + str(_8D38) + ' ' + str(_469A) + ' ' + str(_E86C) + ' ' + str(_0CD0) + ' ' + str(_28DE) + ' ' + str(_8F8C) + ' ' + str(_AB52) + ' ' + str(_9A17) + ' ' + str(_713B) + ' ' + str(_919F) + ' ' + str(_56A8) + ' ' + str(_CF87) + ' ' + str(_3CFD) + ' ' + str(_7B46) + ' ' + str(_AF65) + '\n');
			#print("last aggregated line", totalLines)
			fo.write(startTimeStamp + ' ' + str(startTime) + ' ' + str(totalLength) + ' ' + str(maxLength) + ' ' + str(minLength) + ' ' + str(totalPackets) + ' ' + str(countSrc['af65']) + ' ' + str(countSrc['d7b1']) + ' ' + str(countSrc['27a8']) + ' ' + str(countSrc['0000']) + ' ' + str(countSrc['bbb1']) + ' ' + str(countSrc['d7b2']) + ' ' + str(countSrc['36cf']) + ' ' + str(countSrc['8d38']) + ' ' + str(countSrc['469a']) + ' ' + str(countSrc['e86c']) + ' ' + str(countSrc['0cd0']) + ' ' + str(countSrc['28de']) + ' ' + str(countSrc['8f8c']) + ' ' + str(countSrc['ab52']) + ' ' + str(countSrc['9a17']) + ' ' + str(countSrc['71b3']) + ' ' + str(countSrc['919f']) + ' ' + str(countSrc['56a8']) + ' ' + str(countSrc['cf87']) + ' ' + str(countSrc['3cfd']) + ' ' + str(countSrc['7b46']) + ' ' + str(countSrc['0870']) + ' ' + str(countSrc['6541']) + ' ');

#"D7B1" + "27A8"
		
			fo.write(str(countDest['af65']) + ' ' +  str(countDest['d7b1']) + ' ' + str(countDest['27a8']) + ' ' + str(countDest['0000']) + ' ' + str(countDest['bbb1']) + ' ' + str(countDest['d7b2']) + ' ' + str(countDest['36cf']) + ' ' + str(countDest['8d38']) + ' ' + str(countDest['469a']) + ' ' + str(countDest['e86c']) + ' ' + str(countDest['0cd0']) + ' ' + str(countDest['28de']) + ' ' + str(countDest['8f8c']) + ' ' + str(countDest['ab52']) + ' ' + str(countDest['9a17']) + ' ' + str(countDest['71b3']) + ' ' + str(countDest['919f']) + ' ' + str(countDest['56a8']) + ' ' + str(countDest['cf87']) + ' ' + str(countDest['3cfd']) + ' ' + str(countDest['7b46']) + ' ' + str(countDest['0870']) + ' ' + str(countDest['6541']) + '\n');
			

		



		
		
	




