import sys
from datetime import datetime
from datetime import timedelta
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

if len(sys.argv) < 1:
	print("You must enter two arguments: block length in seconds, shift size of block in seconds")
	exit()
else:
	print(sys.argv)

#get block size from args
time = int(sys.argv[1])

#shiftSize = int(sys.argv[2])

#if shiftSize > time:
#	print("Shift Size must be smaller than size of block")
#	exit()

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

		#Determine where next block will start, 1 second after previous block
		if (timeInSeconds - initSeconds >= 1) & (not nextStart): #changed to 5
			nextStart = True
			#print("block will revert to: ", lineNumber)
			revertIndex = index
			#for testing only
			revertLineNumber = lineNumber
			#get the number of seconds the next block starts at
			nextBlockInitSeconds = timeInSeconds
		#check to see if block has ended
		if timeInSeconds >= (initSeconds + time):

			#print("block ended")
			#testing
			lineNumber = revertLineNumber

			index = revertIndex
			nextStart = False	
			initSeconds = nextBlockInitSeconds
			f.seek(revertIndex, 0)

			fo.write(startTimeStamp + ' ' + str(startTime) + ' ' + str(totalLength) + ' ' + str(maxLength) + ' ' + str(minLength) + ' ' + str(totalPackets) + ' ' + str(countSrc['af65']) + ' ' + str(countSrc['d7b1']) + ' ' + str(countSrc['27a8']) + ' ' + str(countDest['af65']) + ' ' +  str(countDest['d7b1']) + ' ' + str(countDest['27a8']) + ' ' + str(countSrc['0000']) + ' ' + str(countSrc['bbb1']) + ' ' + str(countSrc['d7b2']) + ' ' + str(countSrc['36cf']) + ' ' + str(countSrc['8d38']) + ' ' + str(countSrc['469a']) + ' ' + str(countSrc['e86c']) + ' ' + str(countSrc['0cd0']) + ' ' + str(countSrc['28de']) + ' ' + str(countSrc['8f8c']) + ' ' + str(countSrc['ab52']) + ' ' + str(countSrc['9a17']) + ' ' + str(countSrc['71b3']) + ' ' + str(countSrc['919f']) + ' ' + str(countSrc['56a8']) + ' ' + str(countSrc['cf87']) + ' ' + str(countSrc['3cfd']) + ' ' + str(countSrc['7b46']) + ' ' + str(countSrc['0870']) + ' ' + str(countSrc['6541']) + ' ');

#"D7B1" + "27A8"
			
			fo.write(str(countDest['0000']) + ' ' + str(countDest['bbb1']) + ' ' + str(countDest['d7b2']) + ' ' + str(countDest['36cf']) + ' ' + str(countDest['8d38']) + ' ' + str(countDest['469a']) + ' ' + str(countDest['e86c']) + ' ' + str(countDest['0cd0']) + ' ' + str(countDest['28de']) + ' ' + str(countDest['8f8c']) + ' ' + str(countDest['ab52']) + ' ' + str(countDest['9a17']) + ' ' + str(countDest['71b3']) + ' ' + str(countDest['919f']) + ' ' + str(countDest['56a8']) + ' ' + str(countDest['cf87']) + ' ' + str(countDest['3cfd']) + ' ' + str(countDest['7b46']) + ' ' + str(countDest['0870']) + ' ' + str(countDest['6541']) + '\n');

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

		#Add line to aggregate
		else:
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
				fo.write(startTimeStamp + ' ' + str(startTime) + ' ' + str(totalLength) + ' ' + str(maxLength) + ' ' + str(minLength) + ' ' + str(totalPackets) + ' ' + str(countSrc['af65']) + ' ' + str(countSrc['d7b1']) + ' ' + str(countSrc['27a8']) + ' ' + str(countDest['af65']) + ' ' +  str(countDest['d7b1']) + ' ' + str(countDest['27a8']) + ' ' + str(countSrc['0000']) + ' ' + str(countSrc['bbb1']) + ' ' + str(countSrc['d7b2']) + ' ' + str(countSrc['36cf']) + ' ' + str(countSrc['8d38']) + ' ' + str(countSrc['469a']) + ' ' + str(countSrc['e86c']) + ' ' + str(countSrc['0cd0']) + ' ' + str(countSrc['28de']) + ' ' + str(countSrc['8f8c']) + ' ' + str(countSrc['ab52']) + ' ' + str(countSrc['9a17']) + ' ' + str(countSrc['71b3']) + ' ' + str(countSrc['919f']) + ' ' + str(countSrc['56a8']) + ' ' + str(countSrc['cf87']) + ' ' + str(countSrc['3cfd']) + ' ' + str(countSrc['7b46']) + ' ' + str(countSrc['0870']) + ' ' + str(countSrc['6541']) + ' ');

#"D7B1" + "27A8"
			
				fo.write(str(countDest['0000']) + ' ' + str(countDest['bbb1']) + ' ' + str(countDest['d7b2']) + ' ' + str(countDest['36cf']) + ' ' + str(countDest['8d38']) + ' ' + str(countDest['469a']) + ' ' + str(countDest['e86c']) + ' ' + str(countDest['0cd0']) + ' ' + str(countDest['28de']) + ' ' + str(countDest['8f8c']) + ' ' + str(countDest['ab52']) + ' ' + str(countDest['9a17']) + ' ' + str(countDest['71b3']) + ' ' + str(countDest['919f']) + ' ' + str(countDest['56a8']) + ' ' + str(countDest['cf87']) + ' ' + str(countDest['3cfd']) + ' ' + str(countDest['7b46']) + ' ' + str(countDest['0870']) + ' ' + str(countDest['6541']) + '\n');

			
# open file to write agregate to with added labels
#ff = open("wekaFile.txt", "w")
#
## open aggregated file and open up the activity log to assign the apporpiate values to each row
#with open('agregated.txt', 'r') as f:
#	for agrLine in f:
#
#		print("are we working")
#
#		dateStripped = datetime.strptime(agrLine[0:19], "%Y-%m-%dT%H:%M:%S")
#		agregateTime = calendar.timegm(dateStripped.utctimetuple())
#
#		temp2 = ""
#		prev = ""
#
#		with open('CC2531/activitylog.txt', 'r') as f:
#			for line in f:
#		
#				#start time of block
#				dateStripped = datetime.strptime(line[0:19], "%Y-%m-%dT%H:%M:%S")
#				activityLogTime = calendar.timegm(dateStripped.utctimetuple())
#
#				# if we never pass onto the next block AKA our block does not overlap into two activity log rows
#		
#		
#
#				## check to see that we have passed over the corresponding time in the activitylog so we can get the previous value
#				# also check to make sure that the we have not passed over the block of time that our aggregate block covers
#				if agregateTime <= activityLogTime + 1 and activityLogTime + 1 <= agregateTime + time:
#
#					#print("am I working")
#
#					if temp2 == "":
#						temp2 = prev
#
#					if temp2 == "" or temp2 == "U":
#						temp2 = line[20:21]
#					elif temp2 == 'I' and line[20:21] == 'A':
#						temp2 = line[20:21]
#					print(line[20:21])
#
#				# this if statement checks to make sure that code that only overlaps one row of the activity log still gets assigned a value
#				if agregateTime <= activityLogTime + 1 and activityLogTime + 1 >= agregateTime + time and temp2 == "":
#					temp2 = prev
#			
#				prev = line[20:21]
#				print(line)
#				print("previous: " + prev + " current value = : " + temp2)
#				#if agregateTime > activityLogTime:
#				#	#break
#				#	print("passed")
#		
#		#print out row
#		print("result: " + temp2)
#		line = line + " " + temp2 + '\n'
#		
#		i = 0
#		#while line[i] != '\n':
#		#	i+=1
#		#row = line[20:i] + " inactive\n"
#		#fo.write(row);
#		#print(row)
#		line = line.replace(' ',',')
#		ff.write(line);
#		ff.write("hello")
			
			
		
	



