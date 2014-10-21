// TestAoiDlg.cpp : implementation file
//

#include "stdafx.h"
#include "TestAoi.h"
#include "TestAoiDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CTestAoiDlg dialog




CTestAoiDlg::CTestAoiDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CTestAoiDlg::IDD, pParent)
	, m_num(0)
	, m_obj(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_self_obj = NULL;
	m_aoi_map = NULL;
	m_obj_index = 0;
	m_usedtime = 0.0;
	m_tickIndex = 0;
	memset(m_aoi_objs, 0, MAX_OBJS * sizeof(kaoi_obj_t));
	k_core_dump();
	srand((uint)time(NULL));
	
}

CTestAoiDlg::~CTestAoiDlg()
{
	UninitAoiMap();
}

void CTestAoiDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_NUM, m_num);
	DDX_Text(pDX, IDC_EDIT2, m_obj);
}

BEGIN_MESSAGE_MAP(CTestAoiDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BTN_INIT, &CTestAoiDlg::OnBnClickedBtnInit)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_BEN_UP, &CTestAoiDlg::OnBnClickedBenUp)
	ON_BN_CLICKED(IDC_BTN_DOWN, &CTestAoiDlg::OnBnClickedBtnDown)
	ON_BN_CLICKED(IDC_BEN_LEFT, &CTestAoiDlg::OnBnClickedBenLeft)
	ON_BN_CLICKED(IDC_BEN_RIGHT, &CTestAoiDlg::OnBnClickedBenRight)
	ON_BN_CLICKED(IDC_BTN_ADDOBJ, &CTestAoiDlg::OnBnClickedBtnAddobj)
	ON_BN_CLICKED(IDC_BTN_SET, &CTestAoiDlg::OnBnClickedBtnSet)
END_MESSAGE_MAP()


// CTestAoiDlg message handlers

BOOL CTestAoiDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	GetDlgItem(IDC_BTN_ADDOBJ)->EnableWindow(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CTestAoiDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
		
		CDC MemDC;
		CBitmap MemBitmap;
		CDC *pDC = GetDC();
		MemDC.CreateCompatibleDC(NULL);
		MemBitmap.CreateCompatibleBitmap(pDC, MAP_WIDTH + 300, MAP_HEIGHT); 
		CBitmap *pOldBit = MemDC.SelectObject(&MemBitmap); 
		MemDC.FillSolidRect(0, 0, MAP_WIDTH, MAP_HEIGHT, RGB(255,255,255)); 

		MemDC.FillSolidRect(MAP_WIDTH + 4, MAP_HEIGHT + 4, MAP_WIDTH + 200, MAP_HEIGHT + 200, RGB(255,255,255)); 

		ShowTime(&MemDC);

		for (int i = 0 ; i < m_obj_index; i++)
		{
			DrawObj(m_aoi_objs[i], &MemDC);
		}

		pDC->BitBlt(4, 4, MAP_WIDTH - 8, MAP_HEIGHT - 8, &MemDC, 0, 0, SRCCOPY);
		if (m_self_obj)
		{
			pDC->BitBlt(MAP_WIDTH + 4, 4, 200, 200, &MemDC, m_self_obj->x - RADIUS, m_self_obj->y - RADIUS, SRCCOPY);
		}
		
		MemBitmap.DeleteObject(); 
		MemDC.DeleteDC(); 
	}

}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CTestAoiDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CTestAoiDlg::InitAoiMap()
{
	m_logFile.Open("1.txt", CFile::modeCreate | CFile::modeWrite);
	kaoi_map_init(&m_aoi_map, MAP_WIDTH, MAP_HEIGHT, NULL);
	kaoi_map_set_data(m_aoi_map, this);
	SetBkMode(::GetDC(m_hWnd), TRANSPARENT);
	SetTimer(1, 1000, NULL);
	SetTimer(2, 100, NULL);
	GetDlgItem(IDC_BTN_ADDOBJ)->EnableWindow(TRUE);
	m_num = 1;
	UpdateData(FALSE);
}

void CTestAoiDlg::UninitAoiMap()
{
	kaoi_map_uninit(m_aoi_map);
	for (int i = 0; i < m_obj_index; ++i)
	{
		kaoi_obj_uninit(m_aoi_objs[i]);
	}
}

void CTestAoiDlg::DrawObj(kaoi_obj_t obj, CDC * MemDC)
{
	CBrush * pBrush = CBrush::FromHandle((HBRUSH)GetStockObject(NULL_BRUSH));
	CBrush * pOldBrush = MemDC->SelectObject(pBrush);
	if (obj == m_self_obj)
	{
		CPen pen(PS_SOLID,1,RGB(255,0,0)); 
		CPen * pOldPen = MemDC->SelectObject(&pen);
		MemDC->Rectangle(obj->x - obj->radius, obj->y - obj->radius, obj->x + obj->radius, obj->y + obj->radius);
		MemDC->SelectObject(pOldPen);
		COLORREF oldColor = MemDC->GetTextColor();
		MemDC->SetTextColor(RGB(255, 0, 0));
		MemDC->TextOut(obj->x, obj->y, "self");
		MemDC->SetTextColor(oldColor);
	}
	else
	{
		//MemDC->Rectangle(obj->x - obj->radius, obj->y - obj->radius, obj->x + obj->radius, obj->y + obj->radius);
		CString str = "";
		str.Format("%d", obj->id);
		MemDC->TextOut(obj->x, obj->y, str);
	}
	MemDC->SelectObject(pOldBrush);
}

void CTestAoiDlg::ShowTime(CDC * MemDC)
{
	static int i = 0;
	static char c[4] = {'-','\\','|','/'};
	CString timeStr = "";
	timeStr.Format("%c ---- %f", c[i++], m_usedtime);
	if (i >= 4)
	{
		i = 0;
	}
	MemDC->TextOut(10, 10, timeStr);
	MemDC->TextOut(10, 30, m_strMsg);
}

void CTestAoiDlg::ShowAoi(int watcher, int marker, int status)
{
	if (KAOI_STAY == status)
	{
		return;
	}
	if (watcher != m_self_obj->id)
	{
		return;
	}
	m_strMsg.Format("%d -----> %d : %d", watcher, marker, status);
	//m_logFile.WriteString(m_strMsg);
	Invalidate(FALSE);
}

void CTestAoiDlg::ShowMiniMap(kaoi_obj_t obj)
{

}

void CTestAoiDlg::OnBnClickedBtnInit()
{
	// TODO: Add your control notification handler code here
	InitAoiMap();
	GetDlgItem(IDC_BTN_INIT)->EnableWindow(FALSE);
}

void KAoi_cb(kaoi_map_t map, kaoi_obj_t watcher, kaoi_obj_t marker, int status)
{
	CTestAoiDlg * pDlg = (CTestAoiDlg *)kaoi_map_get_data(map);
	pDlg->ShowAoi(watcher->id, marker->id, status);

}

void CTestAoiDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: Add your message handler code here and/or call default
	switch (nIDEvent)
	{
	case 1:
		{
			//CClientDC dc(this);
			//dc.Rectangle(0, 0, MAP_WIDTH, MAP_HEIGHT);
			//dc.Rectangle(1004, 0, 1204, 200);

			//m_logFile.WriteString("start\r\n");

			LARGE_INTEGER t1, t2, tc; 
			QueryPerformanceFrequency(&tc);
			QueryPerformanceCounter(&t1);
			kaoi_tick(m_aoi_map, KAoi_cb);			
			QueryPerformanceCounter(&t2);

			//m_logFile.WriteString("end\r\n");
			m_usedtime = (double)(((t2.QuadPart - t1.QuadPart) * 1000.0) / tc.QuadPart);
			//Invalidate(FALSE);

			//5 seconds per move
			if (++m_tickIndex == 5)
			{
				m_tickIndex = 0;
				//get rand target pos for per obj
				for (int i = 0 ; i < m_obj_index; i++)
				{
					kaoi_obj_t obj = (kaoi_obj_t)m_aoi_objs[i];
					if (obj == m_self_obj)
					{
						continue;
					}
					int x = rand() % MAP_WIDTH;
					int y = rand() % MAP_HEIGHT;
					obj->target_x = x;
					obj->target_y = y;
				}
			}
		}
		break;
	case 2:
		{
			//move heartbeat, move to target pos
			for (int i = 0 ; i < m_obj_index; i++)
			{
				kaoi_obj_t obj = (kaoi_obj_t)m_aoi_objs[i];
				if (obj == m_self_obj)
				{
					continue;
				}
				if (obj->target_y != obj->y)
				{
					double s = (obj->target_x - obj->x) / (obj->target_y - obj->y);
					int dx =  (int)(s * 1);
					int dy =  1;
					if (obj->x + dx > MAP_WIDTH)
					{
						obj->x = 0;
					}
					if (obj->y + dy > MAP_HEIGHT)
					{
						obj->y = 0;
					}
					kaoi_move_obj(m_aoi_map, obj, obj->x + dx, obj->y + dy);
				}
			}
			Invalidate(FALSE);
		}
		break;
	}
	
	CDialog::OnTimer(nIDEvent);
}

void CTestAoiDlg::OnBnClickedBenUp()
{
	// TODO: Add your control notification handler code here
	kaoi_move_obj(m_aoi_map, m_self_obj, m_self_obj->x, m_self_obj->y - 5);
	Invalidate(FALSE);
}

void CTestAoiDlg::OnBnClickedBtnDown()
{
	// TODO: Add your control notification handler code here
	kaoi_move_obj(m_aoi_map, m_self_obj, m_self_obj->x, m_self_obj->y + 5);
	Invalidate(FALSE);
}

void CTestAoiDlg::OnBnClickedBenLeft()
{
	// TODO: Add your control notification handler code here
	kaoi_move_obj(m_aoi_map, m_self_obj, m_self_obj->x - 5, m_self_obj->y);
	Invalidate(FALSE);
}

void CTestAoiDlg::OnBnClickedBenRight()
{
	// TODO: Add your control notification handler code here
	kaoi_move_obj(m_aoi_map, m_self_obj, m_self_obj->x + 5, m_self_obj->y);
	Invalidate(FALSE);
}


void CTestAoiDlg::OnBnClickedBtnAddobj()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);

	for (int i = 0; i < m_num; i++)
	{
		int x = rand() % MAP_WIDTH;
		int y = rand() % MAP_HEIGHT;

		kaoi_obj_t obj = NULL;
		kaoi_obj_init(&obj, x, y, KAOI_WATCHER & KAOI_MARKER, RADIUS, NULL);
		obj->id = m_obj_index;
		obj->target_x = 0;
		obj->target_y = 0;
		m_aoi_objs[m_obj_index++] = obj;
		kaoi_add_obj(m_aoi_map, obj);
	}
	m_self_obj = m_aoi_objs[0];
	Invalidate(FALSE);
}

void CTestAoiDlg::OnBnClickedBtnSet()
{
	// TODO: Add your control notification handler code here
	UpdateData(TRUE);
	if (m_obj > m_obj_index)
	{
		return;
	}
	if (NULL == m_aoi_objs[m_obj])
	{
		return ;
	}
	m_self_obj = m_aoi_objs[m_obj];
}
