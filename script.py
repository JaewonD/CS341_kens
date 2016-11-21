f = open("scriptret.txt", "w")
for i in range (200):
	f.write('\t@echo "Trial %d" >> congestionLog.txt\n' % (i+1))
	f.write("\tmake test_part4_only >> congestionLog.txt\n")
	f.write("\tmv TestCongestion1.pcap TestCongestion1_%d.pcap\n" % (i+1))
f.close()