#!/usr/bin/env python
# coding:utf-8
# author: PT
# date: 2017/01/16

import pypinyin as py
import sys

def ConvertStr(st,Picasso=True):
	"""
	str: unicode str
	return pinyin list like 你好=> [u'ni',u'hao']	
	"""
	rLst = []
	lst = py.pinyin(st, style=py.NORMAL)
	for l in lst:
		if Picasso and l and l[0]:
			l[0] = l[0][0].upper() + l[0][1:]
			
		rLst.extend(l)
	return rLst	
if __name__ == "__main__":
	slst = sys.argv[1:]
	if slst:
		for s in slst:	
			print "".join(ConvertStr(s.decode("utf8")))
	else:
		print "No any string args"
