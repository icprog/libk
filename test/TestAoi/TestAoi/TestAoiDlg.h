// TestAoiDlg.h : header file
//

#pragma once

#include "k.h"

#define MAX_OBJS	10240
#define RADIUS		100
#define MAP_WIDTH	1000
#define MAP_HEIGHT	600

// CTestAoiDlg dialog
class CTestAoiDlg : public CDialog
{
// Construction
public:
	CTestAoiDlg(CWnd* pParent = NULL);	// standard constructor
	~CTestAoiDlg();
// Dialog Data
	enum { IDD = IDD_TESTAOI_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	//kaoi
	kaoi_map_t m_aoi_map;
	kaoi_obj_t m_aoi_objs[MAX_OBJS];
	kaoi_obj_t m_self_obj;

	int m_obj_index;
	double m_usedtime;
	CString m_strMsg;

	int m_tickIndex;

	CStdioFile m_logFile;

	void InitAoiMap();
	void UninitAoiMap();
	void DrawObj(kaoi_obj_t obj, CDC * MemDC);
	void ShowTime(CDC * MemDC);
	void ShowAoi(int watcher, int marker, int status);
	void ShowMiniMap(kaoi_obj_t obj);

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedBtnInit();

	afx_msg void OnTimer(UINT_PTR nIDEvent);
	afx_msg void OnBnClickedBenUp();
	afx_msg void OnBnClickedBtnDown();
	afx_msg void OnBnClickedBenLeft();
	afx_msg void OnBnClickedBenRight();
	afx_msg void OnBnClickedBtnAddobj();

	friend void kaoi_tick(ktimer_t timer, int time, int count, void *data);
	friend void KAoi_cb(kaoi_map_t map, kaoi_obj_t watcher, kaoi_obj_t marker, int status);
	int m_num;
	afx_msg void OnBnClickedBtnSet();
	int m_obj;
};
