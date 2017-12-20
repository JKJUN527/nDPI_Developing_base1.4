#!/usr/bin/env python
# coding:utf8
from prettytable import PrettyTable
import csv
import sys
from collections import namedtuple as NP
from convertPinyin import ConvertStr
import datetime

# it must be utf8 csv file
START_ID = 0

Row2 = NP('Row2',['name_zh', 'name_en', 'company', 'macro', 'url', 'nid','update_time','bak'])
def geneLst(fp):
	global START_ID 
	_start_id = START_ID
	reader = csv.reader(file(fp,'rb'))
	MacroFmt = 'NDPI_PROTOCOL_GAME_AUTO_{macro}'
	Row = NP('Row',['name', 'company', 'url'])
	macroSet = set()
	# rLst = []
	# format: name,company,urls,xxx
	for arr in reader:
		# for x in arr:
		#	print x,',',
		
		row = Row(*arr[:3])
		name_zh = row.name.strip()
		name_en = ''.join(ConvertStr(row.name.decode('utf8'))).strip()		 	 
		company_en = ''.join(ConvertStr(row.company.decode('utf8'))).strip()
		name_en = name_en + '_' + company_en
		name_en = name_en.replace('-','_').replace('(','_').replace(')','_')
		# print name_en
		macro = MacroFmt.format(macro=name_en.upper())
		bak = ''

		if macro not in macroSet:
			_start_id = _start_id + 1
			macroSet.add(macro)
		nid = _start_id
		ut = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S' )
		row2 = Row2(*[name_zh,name_en,row.company,macro,row.url,nid,ut,bak])
		# print row2
		# rLst.append(row2)
		yield row2

	# return rLst

def formatList(lst,meta=[],style='l'):
        x = PrettyTable(meta)
        x.header = False
        x.border = False
        rLst = []
        for h in meta:
            x.align[h] = style
        for l in lst:
            x.add_row(l)
        return x

# input a list of Row2
def geneIdAndHostMatch(lst=[]):
	"""return a set [[define],[host_match]]"""
	hmFmt = """{{ "{url}", \t\t\t\t\t"{name_en}", \t\t\t\t\t\t{macro} }},"""
	dfFmt = """#define {macro}\t\t\t\t\t{nid}"""
	dfLst = []
	hmLst = []
	for row in lst:
		flag = 0
		# print row
		for u in row.url.split('|'):
			flag = 1
			hm = hmFmt.format(url=u,name_en=row.name_en,macro=row.macro)
			hmLst.append(hm)
			# print hm
		if flag:
			df = dfFmt.format(macro=row.macro,nid=row.nid)
			dfLst.append(df)
			# print df
	return [dfLst,hmLst]

def geneConfig(lst=[], app_system='app_system.partial.txt', app_rule='app_rule.partial.txt'):
	"""gene app_system and app_rule config
	lst: row2 list
	"""
	gameGroupId = 24
	app_system_fmt = '{nid},{name_en},{name_zh}({company}),,{grpId},1'
	app_rule_fmt = '{nid},{name_zh}({company}),,{nid},1'
	as_lst = []
	ar_lst = []
	with open(app_system,'w') as as_fd:
		with open(app_rule,'w') as ar_fd:
			for row2 in lst:
				line = app_system_fmt.format(nid=row2.nid,name_en=row2.name_en,name_zh=row2.name_zh,company=row2.company,grpId=gameGroupId)
				as_fd.write(line)
				as_fd.write('\n')
				
				line = app_rule_fmt.format(nid=row2.nid,name_en=row2.name_en,name_zh=row2.name_zh,company=row2.company,grpId=gameGroupId)
				ar_fd.write(line)
				ar_fd.write('\n')

def genePrettyDefineAndHostMatch(lst=[]):
        df, hm = geneIdAndHostMatch(lst)
        x_df = formatList([x.split() for x in df], meta=['define', 'macro', 'nid'])
        x_hm = formatList([x.split() for x in hm], meta=['{', 'url', 'name_en', 'macro', '}'])
        return [x_df,x_hm]

def geneDefineAndHostMatchFile(lst=[],define_file='define.txt',host_match_file = 'host_match.txt'):
        x_df, x_hm = genePrettyDefineAndHostMatch(lst)
        with open(define_file,'w') as fd:
			fd.write(x_df.get_string().encode('utf8'))
        with open(host_match_file,'w') as fd:
            fd.write(x_hm.get_string().encode('utf8'))

def geneSQL(rows=[],db='page_games',tb = 'tb_games'):
	"""
	generate sqls by Row2
	rows: Row2 list
	return: a generator of sqls
	"""
	# rLst = []
	# add = rLst.append
	
	yield "USE {db};".format(db=db)
	yield "SET CHARSET UTF8;"
	sqlFmt = """INSERT INTO `{db}`.`{tb}` (`name_zh`, `name_en`, `company`, `macro`, `url`, `nid`, `update_time`) VALUES ('{name_zh}', '{name_en}', '{company}', '{macro}', '{url}', {nid}, '{update_time}');"""
	for row2 in rows:
		sql = sqlFmt.format(db=db,tb=tb,name_zh=row2.name_zh,name_en=row2.name_en,company=row2.company,macro=row2.macro,url=row2.url,nid=row2.nid,update_time=row2.update_time)
		# add(sql)
		yield sql
	# return rLst 
	
def getSqlByFilePath(in_file=None,out_file=None):
	"""
	gene sql file by csv file
	in_file: input csv file path
	out_file: your target sql path
	"""
	row2Lst = geneLst(in_file)
	sqlLst = geneSQL(row2Lst)
	with open(out_file,'w') as fd:
		for sql in sqlLst:
			fd.write(sql)
			fd.write('\n')

def oneKeyGene(src_csv='total.csv'):
    lst = list(geneLst(src_csv))
    print 'gene total.sql'
    getSqlByFilePath(in_file=src_csv,out_file='total.sql')
    print 'gene define.txt and host_match.txt'
    geneDefineAndHostMatchFile(lst)
    print 'gene config file'
    geneConfig(lst)
def main():
	global START_ID
	if sys.argv[1:]:
		fp = sys.argv[1]
		if sys.argv[2:]:
			START_ID = int(sys.argv[2])
		else:
			pass
		# lst = geneLst(fp)
		#r = geneIdAndHostMatch(lst)
                oneKeyGene(fp)
	else:
		print 'You should set a input file'
if __name__ == '__main__':
	main()
