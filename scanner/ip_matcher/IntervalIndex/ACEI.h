/************************************************************************/
/* 
	AdvanceCEI 0621.2007 v1.1
	Yao Qiu-lin (yaoqiulin@software.ict.ac.cn)

	修改：
		1. 转为OO形式
		2. 文件接口改为内存接口

		注意：	PreProcessing后，原则上不该添加查询区间，因为这样会破坏当前数据结构的最优性，
				当然实际使用时支持通过insertIntvl继续插入少量的QueryInterval，如果
				要大量添加查询区间，那么应该根据新的区间集合重新构造索引。
*/
/************************************************************************/

#ifndef _ADVANCECEI_YAOQIULIN_20080509_
#define _ADVANCECEI_YAOQIULIN_20080509_

#include "IntervalIndex.h"

#include <stdlib.h>
#include <stdio.h>
#include <vector>

//#define  u_int unsigned int
typedef unsigned int u_int;

typedef struct _QueryInterval_
{
	u_int l;
	u_int r;
	u_int index;
} _QueryInterval;

typedef struct _HQueryI_
{
	_QueryInterval ** ppQImatrix;
	u_int MAXROWS;
	u_int ROWLEN;
	u_int rowID;//next available
	u_int colID;//next available
	u_int cnt;
}_HQueryI;

typedef struct _IID_ //可以缩减数据结构来减少空间，如果效果不好的话
{
	_QueryInterval * iid;
	struct _IID_ * next;
}_IID;

typedef struct _IIDSet_
{
	_IID *head;
	_IID *tail;
} _IIDSet;

typedef _IIDSet _CEI;

//pack type

typedef struct _SrlIID_ 
{
	_QueryInterval * iid;
}_SrlIID;

typedef struct _SrlIIDSet_
{
	_SrlIID *head;
}_SrlIIDSet;

typedef _SrlIIDSet _SrlCEI;

class ACEI : public CIntervalIndex
{
public:
	//区间的值域是[0, 2^r)
	ACEI(u_int eRange = 32);
	virtual ~ACEI();
	//一组区间，[ a[i], b[i] ]组成一个闭区间
	virtual long long PreProcessing(const std::vector<unsigned int>& a, const std::vector<unsigned int>& b);
	//返回所有包含key的区间的index
	virtual int Find(unsigned int key, unsigned int * result, unsigned int size);

private:
	//init & ruin
	void initQIMatrix();
	void ruinQIMatirc();
	int init();
	void ruin();
	void releaseCEIs(_CEI **ppIIDSet, u_int lCEIsNum);

	//search
	int searchX(unsigned int x, unsigned int * result, unsigned int size);//可以是double，但当前仅需u_int

	//insert
	//void insertIntvl(u_int l, u_int r)
	void addIntvl(u_int ll, u_int lr, _QueryInterval* pQI);//因为是左闭右开，所以输入的两区间端点若相等，那么认为是空区间
	void addFrgmnt(u_int ll, u_int lr, u_int sID, _QueryInterval* pQI);
	void addBtmCEIs(u_int ll, u_int lr, u_int sID, _QueryInterval *pQI);
	void addID(_CEI* pCEI, _QueryInterval* pQI);

	//ultlity
	double getAvrgRng();

	//serialization
	void serializeCEI(_CEI *pCEI, _SrlCEI* pSrlCEI);//suppose pCEI not NULL
	void serialBtmCEIs();
	void serialTopCEIs();
	void serial();

private:
	//input data
	_HQueryI HQI; //插入的区间所在

	//model data
	u_int n; //插入的区间数量
	u_int r; //值域
	u_int L;//L=2^H, Segment Len
	u_int H;//最大VC树高度
	u_int h;//实际VC树高度
	double w; //平均区间长度
	u_int SNum;//Segment Num
	u_int SCEINum;
	unsigned long *pExp2;
	const u_int Exp2Size;
	_CEI *pTopCEIs;
	_CEI **ppBotCEIs;//每个CEIs序列长度为L或H

	//for serial
	_SrlCEI *pTopSrlCEIs;
	_SrlCEI **ppBotSrlCEIs;//每个CEIs序列长度为L或H
};


#endif