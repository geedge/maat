#include <math.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include "ACEI.h"


ACEI::ACEI(unsigned int eRange):Exp2Size(32)
{
	r = int(((unsigned long long)1 << eRange) - 1); //在后续对r的使用中均会先加1
}
ACEI::~ACEI()
{
	ruin();
}

long long ACEI::PreProcessing(const std::vector<u_int> &a, const std::vector<u_int> &b)
{
	if (a.size() != b.size())
		return -1;

	initQIMatrix();
	int i;
	for (i = 0; i < (int)a.size(); i++)
	{
		HQI.ppQImatrix[HQI.rowID][HQI.colID].l = a[i];//be careful
		HQI.ppQImatrix[HQI.rowID][HQI.colID].r = b[i]+1;//内部区间表示为[, )
		HQI.ppQImatrix[HQI.rowID][HQI.colID].index = i;
		++HQI.cnt;

		//adjust QI matrix begin
		HQI.colID = (HQI.colID + 1) % HQI.ROWLEN;
		if(HQI.colID == 0)
		{
			++HQI.rowID;
			if(HQI.rowID < HQI.MAXROWS)
			{
				HQI.ppQImatrix[HQI.rowID] = (_QueryInterval*)malloc(sizeof(_QueryInterval)*HQI.ROWLEN);
			}
			else
			{
				printf("Query Interval matrix run over, reminder discard !!!\n");
				return 1;
			}
		}
		//adjust end
	}
	n = HQI.cnt;
	init();
	return 0;
}
int ACEI::Find(unsigned int key, unsigned int * result, unsigned int size)
{
	return searchX(key, result, size);
}
//input & output
void ACEI::initQIMatrix()
{
	HQI.MAXROWS = 10000;
	HQI.ROWLEN = 1024;
	HQI.ppQImatrix = (_QueryInterval**)malloc(sizeof(_QueryInterval*)*HQI.MAXROWS);
	HQI.ppQImatrix[0] = (_QueryInterval*)malloc(sizeof(_QueryInterval)*HQI.ROWLEN);
	HQI.rowID = 0;
	HQI.colID = 0;
	HQI.cnt = 0;
}
void ACEI::ruinQIMatirc()
{
	int i;
	if(HQI.ppQImatrix)
	{
		for(i = HQI.rowID; i >= 0; i--)
			free(HQI.ppQImatrix[i]);
		free(HQI.ppQImatrix);
		HQI.ppQImatrix = NULL;
	}
	HQI.rowID = 0;
	HQI.colID = 0;
	HQI.cnt = 0;
}
//init & ruin
int ACEI::init()
{
	u_int i,j,k;

	pExp2 = (unsigned long*)malloc(sizeof(unsigned long)*Exp2Size);
	for(i = 0; i < Exp2Size; i++) pExp2[i] = (unsigned long)pow((double)2, (double)i);
	w = getAvrgRng();

	if(n*w>4*r)
	{
		H = (u_int)ceil((double)log(sqrt((double)w/4))/log((double)2));
		h = (u_int)ceil((double)log(sqrt((double)n*w/4/r))/log((double)2));
		if(H <= h) H = h+1;
	}
	else
	{
		H = (u_int)ceil((double)log(sqrt((double)r/3/n+w/6))/log((double)2));
		h = 0;
		if(H <= h) H = h+1;	
	}

	L = pExp2[H];
	SNum = r/L + 1;
	SCEINum = pExp2[h+1];
	pTopCEIs = (_CEI*)malloc(sizeof(_CEI)*SNum*SCEINum); 
	if(!pTopCEIs)
	{
		printf("Malloc error !!!   for pTopCEIs\n");
		return -1;
	}
	memset(pTopCEIs, 0, SNum*SCEINum*sizeof(_CEI));
	ppBotCEIs = (_CEI**)malloc(sizeof(_CEI*) * SNum);
	if(!ppBotCEIs)
	{
		printf("Malloc error !!!   for ppBotCEIs\n");
		return -1;
	}
	memset(ppBotCEIs, 0, SNum*sizeof(_CEI*));

	for (k = 0; k < HQI.cnt; k++)
	{
		i = k / HQI.ROWLEN;
		j = k % HQI.ROWLEN;
		addIntvl(HQI.ppQImatrix[i][j].l, HQI.ppQImatrix[i][j].r, &(HQI.ppQImatrix[i][j]));
	}
	serial();
	return 0;
}

void ACEI::ruin()
{
	u_int i,j;

	free(pExp2);
	//releaseCEIs(&pTopCEIs, SNum*SCEINum);
	//for (i = 0; i < SNum; i++)
	//{
	//	if (ppBotCEIs[i])
	//	{
	//		releaseCEIs(&(ppBotCEIs[i]), L);
	//	}
	//}
	//free(ppBotCEIs);
	for (i = 0; i < SNum*SCEINum; i++)
		if(pTopSrlCEIs[i].head)
			free(pTopSrlCEIs[i].head);
	free(pTopSrlCEIs);
	for (i = 0; i < SNum; i++)
		if(ppBotSrlCEIs[i])
		{
			for (j = 0; j < L; j++)
				if(ppBotSrlCEIs[i][j].head)
					free(ppBotSrlCEIs[i][j].head);
			free(ppBotSrlCEIs[i]);
		}
	free(ppBotSrlCEIs);
	ruinQIMatirc();
}



void ACEI::releaseCEIs(_CEI **ppIIDSet, u_int lCEIsNum)
{
	u_int i;
	_IID * pTID, * pTIDpre;
	for (i = 0; i < lCEIsNum; i++)
	{
		if(((*ppIIDSet)[i]).head != NULL)
		{
			for(pTID = ((*ppIIDSet)[i]).head, pTIDpre = NULL; pTID != NULL;)
			{
				pTIDpre = pTID;
				pTID = pTID->next;
				free(pTIDpre);
			}
		}
	}
	free(*ppIIDSet);
	*ppIIDSet = NULL;
}


//search
int ACEI::searchX(unsigned int x, unsigned int * result, unsigned int size)
{
	std::vector<u_int> vecui;
	u_int sID, uID, dID, lx;
	u_int i;
	_SrlIID *pIID;

	lx = x;

	//if(lx >= r) return vecui;
	if(lx > r) 
		return 0;

	sID = lx >> H;
	dID = lx - (sID << H);
	uID = (dID >> (H - h)) + pExp2[h];

	//lx = (u_int)floor(x);
	//sID = lx / L;
	//dID = lx % L;
	//uID = dID / pExp2[H-h] + pExp2[h];

	//if (fpQueryRslt) fprintf(fpQueryRslt, "%10.6lf\tin  ", x);
	//else printf("%10.6lf\tin  ", x);
	unsigned int n = 0;
	if(ppBotSrlCEIs[sID] && ppBotSrlCEIs[sID][dID].head != NULL)
	{
		for (pIID = ppBotSrlCEIs[sID][dID].head; pIID->iid != NULL; pIID++)
		{
			if(n >= size)
			{
				return n;
			}
			result[n++] = pIID->iid->index;
		}
	}
	for (i = 0; i <= h; i++)
	{
		if (pTopSrlCEIs[sID*SCEINum+uID].head != NULL)
		{
			for (pIID = pTopSrlCEIs[sID*SCEINum+uID].head; pIID->iid != NULL; pIID++)
			{
				if(n >= size)
				{
					return n;
				}
				result[n++] = pIID->iid->index;
			}
		}
		uID >>= 1; 
	}
	return n;
}

//insert
//void insertIntvl(u_int l, u_int r)
//{
//	_QueryInterval * pQI = (_QueryInterval*)malloc(sizeof(_QueryInterval));
//	MemCst += sizeof(_QueryInterval);//for stat.
//	pQI->l = l;
//	pQI->r = r;
//	pQI->next = NULL;
//	if (HQI.head != NULL)
//	{
//		HQI.tail->next = pQI;
//		HQI.tail = pQI;
//	}
//	else
//	{
//		HQI.head = HQI.tail = pQI;
//	}
//	HQI.len ++;
//	addIntvl(l, r, pQI);
//}
void ACEI::addIntvl(u_int ll, u_int lr, _QueryInterval* pQI)//因为是左闭右开，所以输入的两区间端点若相等，那么认为是空区间
{
	unsigned long long lft = ll;
	unsigned long long rght = lr;
	if (!lr)
		rght += ((unsigned long long)1 << 32);
	u_int sLID, sRID;
	u_int i;
	sLID = (u_int)ceil((double)lft/L);
	sRID = (u_int)floor((double)rght/L);
	
	if (sLID > sRID) addFrgmnt(ll, lr, sRID, pQI);
	else 
	{
		if (sLID < sRID)
		{
			for(i = sLID; i < sRID; i++) addID(&(pTopCEIs[i*SCEINum+1]), pQI);
		}
		if (lft < (unsigned long long)sLID * L) addFrgmnt(ll, sLID*L, sLID-1, pQI);
		if (rght > (unsigned long long)sRID * L) addFrgmnt(sRID*L, lr, sRID, pQI);
	}
}
void ACEI::addFrgmnt(u_int ll, u_int lr, u_int sID, _QueryInterval* pQI)//lr 可以为0，只要L不等于2^32，就不会再出现区间右端点溢出的情况
{
	u_int lft = ll % L;
	u_int rght = lr % L; 
	u_int sLID, sRID;
	u_int i,k;
	if(!rght) rght+= L;
	sLID = (u_int)ceil((double)lft/pExp2[H-h]);
	sRID = (u_int)floor((double)rght/pExp2[H-h]);
	if (sLID > sRID) addBtmCEIs(lft, rght, sID,  pQI);
	else 
	{
		if (lft < sLID * pExp2[H-h]) addBtmCEIs(lft, sLID*pExp2[H-h], sID, pQI);
		if (rght > sRID * pExp2[H-h]) addBtmCEIs(sRID*pExp2[H-h], rght, sID, pQI);
		if (sLID < sRID)
		{
			sLID += pExp2[h];
			sRID += pExp2[h];
			i = 1;
			k = sRID - sLID;
			while(1)
			{
				if (sLID % 2 == 0 && i*2 <= k)
				{
					sLID /= 2;
					i *= 2;
				}
				else
				{
					addID(&(pTopCEIs[sID*SCEINum+sLID]), pQI);
					sLID = sRID + i - k;
					k = k - i;
					i = 1;
					if (k == 0) return;
				}
			}
		}
	}
	return;
}
void ACEI::addBtmCEIs(u_int ll, u_int lr, u_int sID, _QueryInterval *pQI)
{
	u_int i;
	if (ppBotCEIs[sID] == NULL && ll < lr)
	{
		ppBotCEIs[sID] = (_CEI*)malloc(sizeof(_CEI) * L);
		memset(ppBotCEIs[sID], 0, sizeof(_CEI)*L);
	}
	for (i = ll; i < lr; i++)
		addID(&(ppBotCEIs[sID][i]), pQI);
}
void ACEI::addID(_CEI* pCEI, _QueryInterval* pQI)
{
	_IID *pNewIID = (_IID*)malloc(sizeof(_IID));
	pNewIID->iid = pQI;
	pNewIID->next = NULL;
	
	if (pCEI->head != NULL)
	{
		pCEI->tail->next = pNewIID;
		pCEI->tail = pNewIID;
	}
	else
	{
		pCEI->head = pCEI->tail = pNewIID;
	}
}

//ultlity
double ACEI::getAvrgRng()
{
	double d = 0;
	u_int i,j,k;
	if (HQI.cnt == 0)
	{
		printf("!!! NO QueryISet loaded when calc w\n");
		return 0;
	}
	for (k = 0; k < HQI.cnt; k++)
	{
		i = k / HQI.ROWLEN;
		j = k % HQI.ROWLEN;
		d += HQI.ppQImatrix[i][j].r - HQI.ppQImatrix[i][j].l;
	}
	return d / n;
}

//serialization
void ACEI::serializeCEI(_CEI *pCEI, _SrlCEI* pSrlCEI)//suppose pCEI not NULL
{
	u_int i,num = 0;
	_IID *pIID;
	for(pIID = pCEI->head; pIID; ++num, pIID = pIID->next);
	pSrlCEI->head = (_SrlIID*)malloc(sizeof(_SrlIID)*(num+1));
	for (i = 0, pIID = pCEI->head; pIID; i++)
	{
		(pSrlCEI->head)[i].iid = pIID->iid;
		pIID = pIID->next;
		//free(pIIDpre);
	}
	((pSrlCEI->head)[num]).iid = NULL;
}
void ACEI::serialBtmCEIs()
{
	u_int i,j;
	ppBotSrlCEIs = (_SrlCEI**)malloc(sizeof(_SrlCEI*)*SNum);
	memset(ppBotSrlCEIs, 0, sizeof(_SrlCEI*)*SNum);
	for (i = 0; i < SNum; i++)
	{
		if (ppBotCEIs[i])
		{
			ppBotSrlCEIs[i] = (_SrlCEI*)malloc(sizeof(_SrlCEI)*L);
			memset(ppBotSrlCEIs[i], 0, sizeof(_SrlCEI)*L);
			for (j = 0; j < L; j++)
				if (ppBotCEIs[i][j].head)
					serializeCEI(&(ppBotCEIs[i][j]), &(ppBotSrlCEIs[i][j]));
				else
					ppBotSrlCEIs[i][j].head = NULL;
			//free(ppBotCEIs[i]);
		}
	}
	//free(ppBotCEIs);
}

void ACEI::serialTopCEIs()
{
	u_int i;
	pTopSrlCEIs = (_SrlCEI*)malloc(sizeof(_SrlCEI)*SNum*SCEINum);
	memset(pTopSrlCEIs, 0, sizeof(_SrlCEI)*SNum*SCEINum);
	for (i = 0; i < SNum*SCEINum; i++)
	{
		if (pTopCEIs[i].head)
			serializeCEI(&(pTopCEIs[i]), &(pTopSrlCEIs[i]));
	}
	//free(pTopCEIs);
}

void ACEI::serial()
{
	u_int i;
	serialTopCEIs();
	serialBtmCEIs();
	releaseCEIs(&pTopCEIs, SNum*SCEINum);
	for(i = 0; i < SNum; i++)
	{
		if(ppBotCEIs[i])
			releaseCEIs(&(ppBotCEIs[i]), L);
	}
	free(ppBotCEIs);
}
