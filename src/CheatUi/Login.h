#pragma once


// Login 对话框

class Login : public CDialogEx
{
	DECLARE_DYNAMIC(Login)

public:
	Login(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~Login();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LOGINVMM };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedLogin();
  void AntiDebugerAndLockUser();
	virtual BOOL OnInitDialog();
	// 用户名
	CEdit UserName;
	// 密码
	CEdit PassWord;
	virtual BOOL DestroyWindow();
  
	afx_msg
		void RunDebuger(int id);
	void OnBnClickedDebugOpen1();
  CString OpenDebugFile();
	afx_msg void OnBnClickedDebugOpen2();
  afx_msg void OnBnClickedDebugOpen3();
  afx_msg void OnBnClickedDebugOpen4();
  afx_msg void OnBnClickedNoept();
  afx_msg void OnBnClickedUseept();
  afx_msg void OnBnClickedRead1();
  afx_msg void OnBnClickedRead2();
};
