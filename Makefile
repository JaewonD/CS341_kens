.PHONY: all clean

MAKE=make

DIRS=
SRCDIR=app
OUTPUT_DIR=build

all:
	@$(MAKE) --directory=src all
	@for dir in $(SRCDIR)/*; do \
		if [ -f $$dir/Makefile ]; then \
			$(MAKE) --directory=$$dir all; \
		fi ; \
	done

clean:
	rm -f *.o $(OUTPUT_DIR)/*.pcap *.pcap *.xml
	rm -rf $(OUTPUT_DIR)/html
	@$(MAKE) --directory=src clean
	@for dir in $(SRCDIR)/*; do \
		if [ -f $$dir/Makefile ]; then \
			$(MAKE) --directory=$$dir clean; \
		fi ; \
	done

depend:
	@$(MAKE) --directory=src depend
	@for dir in $(SRCDIR)/*; do \
		if [ -f $$dir/Makefile ]; then \
			$(MAKE) --directory=$$dir depend; \
		fi ; \
	done

test: test_part1 test_part2 test_part3 test_part4

test_part1: all
	@echo "Running test cases for project1..."
	@-build/testTCP --gtest_filter="TestEnv_Reliable.TestOpen:TestEnv_Reliable.TestBind_*" --gtest_output=xml:part1.xml

test_part2: test_part1
	@echo "Running test cases for project2..."
	@-build/testTCP --gtest_filter="TestEnv_Reliable.TestAccept_*:TestEnv_Any.TestAccept_*:TestEnv_Any.TestConnect_*:TestEnv_Any.TestClose_*" --gtest_output=xml:part2.xml

test_part3: test_part2
	@echo "Running test cases for project3..."
	@-build/testTCP --gtest_filter="TestEnv_Any.TestTransfer_*" --gtest_output=xml:part3.xml

test_part4: test_part3
	@echo "Running test cases for project4..."
	@-build/testTCP --gtest_filter="TestEnv_Congestion*" --gtest_output=xml:part4.xml
	@echo "Note that passing this test does not mean that you are finished."
	@echo "Check the pcap file that you have implemented congestion control well."

test_part4_only:
	@echo "Running test cases for project4..."
	@-build/testTCP --gtest_filter="TestEnv_Congestion*" --gtest_output=xml:part4.xml
	@echo "Note that passing this test does not mean that you are finished."
	@echo "Check the pcap file that you have implemented congestion control well."

test_part4_200:
	make all
	@echo "Trial 1" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_1.pcap
	@echo "Trial 2" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_2.pcap
	@echo "Trial 3" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_3.pcap
	@echo "Trial 4" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_4.pcap
	@echo "Trial 5" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_5.pcap
	@echo "Trial 6" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_6.pcap
	@echo "Trial 7" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_7.pcap
	@echo "Trial 8" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_8.pcap
	@echo "Trial 9" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_9.pcap
	@echo "Trial 10" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_10.pcap
	@echo "Trial 11" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_11.pcap
	@echo "Trial 12" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_12.pcap
	@echo "Trial 13" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_13.pcap
	@echo "Trial 14" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_14.pcap
	@echo "Trial 15" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_15.pcap
	@echo "Trial 16" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_16.pcap
	@echo "Trial 17" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_17.pcap
	@echo "Trial 18" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_18.pcap
	@echo "Trial 19" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_19.pcap
	@echo "Trial 20" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_20.pcap
	@echo "Trial 21" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_21.pcap
	@echo "Trial 22" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_22.pcap
	@echo "Trial 23" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_23.pcap
	@echo "Trial 24" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_24.pcap
	@echo "Trial 25" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_25.pcap
	@echo "Trial 26" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_26.pcap
	@echo "Trial 27" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_27.pcap
	@echo "Trial 28" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_28.pcap
	@echo "Trial 29" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_29.pcap
	@echo "Trial 30" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_30.pcap
	@echo "Trial 31" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_31.pcap
	@echo "Trial 32" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_32.pcap
	@echo "Trial 33" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_33.pcap
	@echo "Trial 34" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_34.pcap
	@echo "Trial 35" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_35.pcap
	@echo "Trial 36" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_36.pcap
	@echo "Trial 37" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_37.pcap
	@echo "Trial 38" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_38.pcap
	@echo "Trial 39" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_39.pcap
	@echo "Trial 40" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_40.pcap
	@echo "Trial 41" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_41.pcap
	@echo "Trial 42" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_42.pcap
	@echo "Trial 43" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_43.pcap
	@echo "Trial 44" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_44.pcap
	@echo "Trial 45" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_45.pcap
	@echo "Trial 46" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_46.pcap
	@echo "Trial 47" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_47.pcap
	@echo "Trial 48" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_48.pcap
	@echo "Trial 49" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_49.pcap
	@echo "Trial 50" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_50.pcap
	@echo "Trial 51" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_51.pcap
	@echo "Trial 52" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_52.pcap
	@echo "Trial 53" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_53.pcap
	@echo "Trial 54" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_54.pcap
	@echo "Trial 55" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_55.pcap
	@echo "Trial 56" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_56.pcap
	@echo "Trial 57" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_57.pcap
	@echo "Trial 58" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_58.pcap
	@echo "Trial 59" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_59.pcap
	@echo "Trial 60" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_60.pcap
	@echo "Trial 61" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_61.pcap
	@echo "Trial 62" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_62.pcap
	@echo "Trial 63" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_63.pcap
	@echo "Trial 64" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_64.pcap
	@echo "Trial 65" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_65.pcap
	@echo "Trial 66" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_66.pcap
	@echo "Trial 67" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_67.pcap
	@echo "Trial 68" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_68.pcap
	@echo "Trial 69" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_69.pcap
	@echo "Trial 70" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_70.pcap
	@echo "Trial 71" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_71.pcap
	@echo "Trial 72" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_72.pcap
	@echo "Trial 73" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_73.pcap
	@echo "Trial 74" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_74.pcap
	@echo "Trial 75" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_75.pcap
	@echo "Trial 76" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_76.pcap
	@echo "Trial 77" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_77.pcap
	@echo "Trial 78" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_78.pcap
	@echo "Trial 79" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_79.pcap
	@echo "Trial 80" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_80.pcap
	@echo "Trial 81" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_81.pcap
	@echo "Trial 82" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_82.pcap
	@echo "Trial 83" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_83.pcap
	@echo "Trial 84" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_84.pcap
	@echo "Trial 85" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_85.pcap
	@echo "Trial 86" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_86.pcap
	@echo "Trial 87" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_87.pcap
	@echo "Trial 88" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_88.pcap
	@echo "Trial 89" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_89.pcap
	@echo "Trial 90" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_90.pcap
	@echo "Trial 91" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_91.pcap
	@echo "Trial 92" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_92.pcap
	@echo "Trial 93" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_93.pcap
	@echo "Trial 94" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_94.pcap
	@echo "Trial 95" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_95.pcap
	@echo "Trial 96" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_96.pcap
	@echo "Trial 97" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_97.pcap
	@echo "Trial 98" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_98.pcap
	@echo "Trial 99" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_99.pcap
	@echo "Trial 100" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_100.pcap
	@echo "Trial 101" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_101.pcap
	@echo "Trial 102" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_102.pcap
	@echo "Trial 103" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_103.pcap
	@echo "Trial 104" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_104.pcap
	@echo "Trial 105" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_105.pcap
	@echo "Trial 106" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_106.pcap
	@echo "Trial 107" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_107.pcap
	@echo "Trial 108" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_108.pcap
	@echo "Trial 109" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_109.pcap
	@echo "Trial 110" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_110.pcap
	@echo "Trial 111" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_111.pcap
	@echo "Trial 112" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_112.pcap
	@echo "Trial 113" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_113.pcap
	@echo "Trial 114" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_114.pcap
	@echo "Trial 115" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_115.pcap
	@echo "Trial 116" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_116.pcap
	@echo "Trial 117" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_117.pcap
	@echo "Trial 118" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_118.pcap
	@echo "Trial 119" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_119.pcap
	@echo "Trial 120" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_120.pcap
	@echo "Trial 121" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_121.pcap
	@echo "Trial 122" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_122.pcap
	@echo "Trial 123" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_123.pcap
	@echo "Trial 124" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_124.pcap
	@echo "Trial 125" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_125.pcap
	@echo "Trial 126" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_126.pcap
	@echo "Trial 127" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_127.pcap
	@echo "Trial 128" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_128.pcap
	@echo "Trial 129" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_129.pcap
	@echo "Trial 130" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_130.pcap
	@echo "Trial 131" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_131.pcap
	@echo "Trial 132" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_132.pcap
	@echo "Trial 133" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_133.pcap
	@echo "Trial 134" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_134.pcap
	@echo "Trial 135" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_135.pcap
	@echo "Trial 136" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_136.pcap
	@echo "Trial 137" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_137.pcap
	@echo "Trial 138" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_138.pcap
	@echo "Trial 139" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_139.pcap
	@echo "Trial 140" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_140.pcap
	@echo "Trial 141" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_141.pcap
	@echo "Trial 142" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_142.pcap
	@echo "Trial 143" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_143.pcap
	@echo "Trial 144" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_144.pcap
	@echo "Trial 145" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_145.pcap
	@echo "Trial 146" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_146.pcap
	@echo "Trial 147" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_147.pcap
	@echo "Trial 148" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_148.pcap
	@echo "Trial 149" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_149.pcap
	@echo "Trial 150" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_150.pcap
	@echo "Trial 151" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_151.pcap
	@echo "Trial 152" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_152.pcap
	@echo "Trial 153" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_153.pcap
	@echo "Trial 154" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_154.pcap
	@echo "Trial 155" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_155.pcap
	@echo "Trial 156" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_156.pcap
	@echo "Trial 157" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_157.pcap
	@echo "Trial 158" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_158.pcap
	@echo "Trial 159" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_159.pcap
	@echo "Trial 160" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_160.pcap
	@echo "Trial 161" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_161.pcap
	@echo "Trial 162" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_162.pcap
	@echo "Trial 163" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_163.pcap
	@echo "Trial 164" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_164.pcap
	@echo "Trial 165" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_165.pcap
	@echo "Trial 166" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_166.pcap
	@echo "Trial 167" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_167.pcap
	@echo "Trial 168" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_168.pcap
	@echo "Trial 169" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_169.pcap
	@echo "Trial 170" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_170.pcap
	@echo "Trial 171" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_171.pcap
	@echo "Trial 172" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_172.pcap
	@echo "Trial 173" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_173.pcap
	@echo "Trial 174" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_174.pcap
	@echo "Trial 175" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_175.pcap
	@echo "Trial 176" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_176.pcap
	@echo "Trial 177" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_177.pcap
	@echo "Trial 178" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_178.pcap
	@echo "Trial 179" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_179.pcap
	@echo "Trial 180" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_180.pcap
	@echo "Trial 181" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_181.pcap
	@echo "Trial 182" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_182.pcap
	@echo "Trial 183" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_183.pcap
	@echo "Trial 184" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_184.pcap
	@echo "Trial 185" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_185.pcap
	@echo "Trial 186" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_186.pcap
	@echo "Trial 187" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_187.pcap
	@echo "Trial 188" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_188.pcap
	@echo "Trial 189" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_189.pcap
	@echo "Trial 190" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_190.pcap
	@echo "Trial 191" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_191.pcap
	@echo "Trial 192" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_192.pcap
	@echo "Trial 193" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_193.pcap
	@echo "Trial 194" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_194.pcap
	@echo "Trial 195" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_195.pcap
	@echo "Trial 196" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_196.pcap
	@echo "Trial 197" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_197.pcap
	@echo "Trial 198" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_198.pcap
	@echo "Trial 199" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_199.pcap
	@echo "Trial 200" >> congestionLog.txt
	make test_part4_only >> congestionLog.txt
	mv TestCongestion1.pcap TestCongestion1_200.pcap
	

doxygen:
	doxygen doxygen/Doxyfile

.PHONY: all clean test test_part1 test_part2 test_part3 test_part4 depend doxygen
