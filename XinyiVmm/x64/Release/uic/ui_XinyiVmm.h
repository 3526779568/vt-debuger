/********************************************************************************
** Form generated from reading UI file 'XinyiVmm.ui'
**
** Created by: Qt User Interface Compiler version 5.15.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_XINYIVMM_H
#define UI_XINYIVMM_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_XinyiVmmClass
{
public:
    QWidget *centralWidget;
    QGroupBox *groupBox;
    QLabel *label;
    QLabel *label_2;
    QLabel *sysinfo;
    QLabel *cpuinfo;
    QGroupBox *groupBox_2;
    QLineEdit *username;
    QLineEdit *password;
    QPushButton *Login;
    QGroupBox *groupBox_3;
    QRadioButton *unuse_ept;
    QRadioButton *use_ept;
    QGroupBox *groupBox_4;
    QRadioButton *unuse_mode;
    QRadioButton *use_mode;
    QGroupBox *groupBox_5;
    QLineEdit *DebugPath1;
    QPushButton *Open1;
    QLineEdit *DebugPath2;
    QPushButton *Open2;
    QLineEdit *DebugPath3;
    QPushButton *Open3;
    QLineEdit *DebugPath4;
    QPushButton *Open4;
    QGroupBox *groupBox_6;
    QCheckBox *AntiInterference;
    QCheckBox *ProtectDebuger;
    QCheckBox *Performance;
    QCheckBox *antihardware;
    QCheckBox *infbreakpoint;
    QCheckBox *disablethread;
    QCheckBox *supercontext;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *XinyiVmmClass)
    {
        if (XinyiVmmClass->objectName().isEmpty())
            XinyiVmmClass->setObjectName(QString::fromUtf8("XinyiVmmClass"));
        XinyiVmmClass->resize(315, 515);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/icon/20201125095101605_easyicon_net_32.ico"), QSize(), QIcon::Normal, QIcon::Off);
        XinyiVmmClass->setWindowIcon(icon);
        XinyiVmmClass->setStyleSheet(QString::fromUtf8(""));
        centralWidget = new QWidget(XinyiVmmClass);
        centralWidget->setObjectName(QString::fromUtf8("centralWidget"));
        groupBox = new QGroupBox(centralWidget);
        groupBox->setObjectName(QString::fromUtf8("groupBox"));
        groupBox->setGeometry(QRect(1, 10, 311, 61));
        label = new QLabel(groupBox);
        label->setObjectName(QString::fromUtf8("label"));
        label->setGeometry(QRect(11, 21, 48, 16));
        label_2 = new QLabel(groupBox);
        label_2->setObjectName(QString::fromUtf8("label_2"));
        label_2->setGeometry(QRect(11, 41, 42, 16));
        sysinfo = new QLabel(groupBox);
        sysinfo->setObjectName(QString::fromUtf8("sysinfo"));
        sysinfo->setGeometry(QRect(68, 21, 231, 16));
        cpuinfo = new QLabel(groupBox);
        cpuinfo->setObjectName(QString::fromUtf8("cpuinfo"));
        cpuinfo->setGeometry(QRect(68, 41, 231, 16));
        groupBox_2 = new QGroupBox(centralWidget);
        groupBox_2->setObjectName(QString::fromUtf8("groupBox_2"));
        groupBox_2->setGeometry(QRect(1, 80, 311, 80));
        username = new QLineEdit(groupBox_2);
        username->setObjectName(QString::fromUtf8("username"));
        username->setGeometry(QRect(10, 20, 171, 20));
        password = new QLineEdit(groupBox_2);
        password->setObjectName(QString::fromUtf8("password"));
        password->setGeometry(QRect(10, 50, 171, 20));
        Login = new QPushButton(groupBox_2);
        Login->setObjectName(QString::fromUtf8("Login"));
        Login->setGeometry(QRect(190, 20, 111, 51));
        groupBox_3 = new QGroupBox(centralWidget);
        groupBox_3->setObjectName(QString::fromUtf8("groupBox_3"));
        groupBox_3->setGeometry(QRect(1, 170, 171, 80));
        unuse_ept = new QRadioButton(groupBox_3);
        unuse_ept->setObjectName(QString::fromUtf8("unuse_ept"));
        unuse_ept->setGeometry(QRect(10, 20, 91, 16));
        unuse_ept->setChecked(true);
        use_ept = new QRadioButton(groupBox_3);
        use_ept->setObjectName(QString::fromUtf8("use_ept"));
        use_ept->setGeometry(QRect(10, 50, 161, 16));
        groupBox_4 = new QGroupBox(centralWidget);
        groupBox_4->setObjectName(QString::fromUtf8("groupBox_4"));
        groupBox_4->setGeometry(QRect(180, 170, 132, 80));
        unuse_mode = new QRadioButton(groupBox_4);
        unuse_mode->setObjectName(QString::fromUtf8("unuse_mode"));
        unuse_mode->setGeometry(QRect(10, 20, 89, 16));
        unuse_mode->setChecked(true);
        use_mode = new QRadioButton(groupBox_4);
        use_mode->setObjectName(QString::fromUtf8("use_mode"));
        use_mode->setGeometry(QRect(10, 50, 89, 16));
        groupBox_5 = new QGroupBox(centralWidget);
        groupBox_5->setObjectName(QString::fromUtf8("groupBox_5"));
        groupBox_5->setGeometry(QRect(1, 350, 311, 141));
        DebugPath1 = new QLineEdit(groupBox_5);
        DebugPath1->setObjectName(QString::fromUtf8("DebugPath1"));
        DebugPath1->setGeometry(QRect(10, 20, 211, 23));
        DebugPath1->setReadOnly(true);
        Open1 = new QPushButton(groupBox_5);
        Open1->setObjectName(QString::fromUtf8("Open1"));
        Open1->setEnabled(false);
        Open1->setGeometry(QRect(230, 20, 75, 23));
        Open1->setCheckable(false);
        Open1->setChecked(false);
        DebugPath2 = new QLineEdit(groupBox_5);
        DebugPath2->setObjectName(QString::fromUtf8("DebugPath2"));
        DebugPath2->setGeometry(QRect(10, 50, 211, 23));
        DebugPath2->setReadOnly(true);
        Open2 = new QPushButton(groupBox_5);
        Open2->setObjectName(QString::fromUtf8("Open2"));
        Open2->setEnabled(false);
        Open2->setGeometry(QRect(230, 50, 75, 23));
        DebugPath3 = new QLineEdit(groupBox_5);
        DebugPath3->setObjectName(QString::fromUtf8("DebugPath3"));
        DebugPath3->setGeometry(QRect(10, 80, 211, 23));
        DebugPath3->setReadOnly(true);
        Open3 = new QPushButton(groupBox_5);
        Open3->setObjectName(QString::fromUtf8("Open3"));
        Open3->setEnabled(false);
        Open3->setGeometry(QRect(230, 80, 75, 23));
        DebugPath4 = new QLineEdit(groupBox_5);
        DebugPath4->setObjectName(QString::fromUtf8("DebugPath4"));
        DebugPath4->setGeometry(QRect(10, 110, 211, 23));
        DebugPath4->setReadOnly(true);
        Open4 = new QPushButton(groupBox_5);
        Open4->setObjectName(QString::fromUtf8("Open4"));
        Open4->setEnabled(false);
        Open4->setGeometry(QRect(230, 110, 75, 23));
        groupBox_6 = new QGroupBox(centralWidget);
        groupBox_6->setObjectName(QString::fromUtf8("groupBox_6"));
        groupBox_6->setGeometry(QRect(1, 260, 311, 81));
        AntiInterference = new QCheckBox(groupBox_6);
        AntiInterference->setObjectName(QString::fromUtf8("AntiInterference"));
        AntiInterference->setGeometry(QRect(10, 20, 71, 16));
        AntiInterference->setChecked(true);
        ProtectDebuger = new QCheckBox(groupBox_6);
        ProtectDebuger->setObjectName(QString::fromUtf8("ProtectDebuger"));
        ProtectDebuger->setGeometry(QRect(90, 20, 101, 16));
        ProtectDebuger->setChecked(true);
        Performance = new QCheckBox(groupBox_6);
        Performance->setObjectName(QString::fromUtf8("Performance"));
        Performance->setGeometry(QRect(200, 20, 71, 16));
        Performance->setChecked(true);
        antihardware = new QCheckBox(groupBox_6);
        antihardware->setObjectName(QString::fromUtf8("antihardware"));
        antihardware->setGeometry(QRect(10, 40, 91, 16));
        antihardware->setChecked(true);
        infbreakpoint = new QCheckBox(groupBox_6);
        infbreakpoint->setObjectName(QString::fromUtf8("infbreakpoint"));
        infbreakpoint->setEnabled(false);
        infbreakpoint->setGeometry(QRect(200, 40, 111, 16));
        infbreakpoint->setChecked(true);
        disablethread = new QCheckBox(groupBox_6);
        disablethread->setObjectName(QString::fromUtf8("disablethread"));
        disablethread->setGeometry(QRect(100, 40, 81, 16));
        disablethread->setChecked(false);
        supercontext = new QCheckBox(groupBox_6);
        supercontext->setObjectName(QString::fromUtf8("supercontext"));
        supercontext->setGeometry(QRect(10, 60, 81, 16));
        XinyiVmmClass->setCentralWidget(centralWidget);
        statusBar = new QStatusBar(XinyiVmmClass);
        statusBar->setObjectName(QString::fromUtf8("statusBar"));
        XinyiVmmClass->setStatusBar(statusBar);

        retranslateUi(XinyiVmmClass);
        QObject::connect(Login, SIGNAL(clicked()), XinyiVmmClass, SLOT(LoginClicked()));
        QObject::connect(Open1, SIGNAL(clicked()), XinyiVmmClass, SLOT(Open1Clicked()));
        QObject::connect(Open2, SIGNAL(clicked()), XinyiVmmClass, SLOT(Open2Clicked()));
        QObject::connect(Open3, SIGNAL(clicked()), XinyiVmmClass, SLOT(Open3Clicked()));
        QObject::connect(Open4, SIGNAL(clicked()), XinyiVmmClass, SLOT(Open4Clicked()));
        QObject::connect(AntiInterference, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));
        QObject::connect(ProtectDebuger, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));
        QObject::connect(Performance, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));
        QObject::connect(antihardware, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));
        QObject::connect(disablethread, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));
        QObject::connect(supercontext, SIGNAL(clicked()), XinyiVmmClass, SLOT(ClickConf()));

        QMetaObject::connectSlotsByName(XinyiVmmClass);
    } // setupUi

    void retranslateUi(QMainWindow *XinyiVmmClass)
    {
        XinyiVmmClass->setWindowTitle(QCoreApplication::translate("XinyiVmmClass", "XinyiVmm", nullptr));
        groupBox->setTitle(QCoreApplication::translate("XinyiVmmClass", "\347\263\273\347\273\237\344\277\241\346\201\257", nullptr));
        label->setText(QCoreApplication::translate("XinyiVmmClass", "\347\263\273\347\273\237\347\211\210\346\234\254", nullptr));
        label_2->setText(QCoreApplication::translate("XinyiVmmClass", "CPU\345\236\213\345\217\267", nullptr));
#if QT_CONFIG(statustip)
        sysinfo->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\347\231\273\345\275\225\345\215\241\346\255\273\350\201\224\347\263\273\344\275\234\350\200\205", nullptr));
#endif // QT_CONFIG(statustip)
        sysinfo->setText(QString());
#if QT_CONFIG(statustip)
        cpuinfo->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\277\205\351\241\273\346\230\257Intel CPU", nullptr));
#endif // QT_CONFIG(statustip)
        cpuinfo->setText(QString());
        groupBox_2->setTitle(QCoreApplication::translate("XinyiVmmClass", "\347\231\273\345\275\225\346\250\241\345\235\227", nullptr));
        username->setPlaceholderText(QCoreApplication::translate("XinyiVmmClass", "\347\224\250\346\210\267\345\220\215", nullptr));
        password->setPlaceholderText(QCoreApplication::translate("XinyiVmmClass", "\345\257\206\347\240\201", nullptr));
        Login->setText(QCoreApplication::translate("XinyiVmmClass", "\347\231\273\345\275\225", nullptr));
        groupBox_3->setTitle(QCoreApplication::translate("XinyiVmmClass", "\350\277\220\350\241\214\346\250\241\345\274\217", nullptr));
#if QT_CONFIG(statustip)
        unuse_ept->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\346\216\250\350\215\220\351\246\226\351\200\211", nullptr));
#endif // QT_CONFIG(statustip)
        unuse_ept->setText(QCoreApplication::translate("XinyiVmmClass", "\347\262\276\347\256\200\346\250\241\345\274\217", nullptr));
#if QT_CONFIG(statustip)
        use_ept->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\217\257\345\260\235\350\257\225\346\226\271\346\241\210", nullptr));
#endif // QT_CONFIG(statustip)
        use_ept->setText(QCoreApplication::translate("XinyiVmmClass", "\345\212\240\345\274\272\346\250\241\345\274\217\357\274\210\351\203\250\345\210\206\346\234\272\345\231\250\345\215\241\351\241\277\357\274\211", nullptr));
        groupBox_4->setTitle(QCoreApplication::translate("XinyiVmmClass", "\344\274\230\345\214\226\351\200\211\351\241\271", nullptr));
        unuse_mode->setText(QCoreApplication::translate("XinyiVmmClass", "\344\274\230\345\214\226\344\270\200", nullptr));
        use_mode->setText(QCoreApplication::translate("XinyiVmmClass", "\344\274\230\345\214\226\344\272\214", nullptr));
        groupBox_5->setTitle(QCoreApplication::translate("XinyiVmmClass", "\350\260\203\350\257\225\345\231\250", nullptr));
        Open1->setText(QCoreApplication::translate("XinyiVmmClass", "\346\211\223\345\274\200", nullptr));
        Open2->setText(QCoreApplication::translate("XinyiVmmClass", "\346\211\223\345\274\200", nullptr));
        Open3->setText(QCoreApplication::translate("XinyiVmmClass", "\346\211\223\345\274\200", nullptr));
        Open4->setText(QCoreApplication::translate("XinyiVmmClass", "\346\211\223\345\274\200", nullptr));
        groupBox_6->setTitle(QCoreApplication::translate("XinyiVmmClass", "\346\266\246\346\273\221\345\211\202", nullptr));
#if QT_CONFIG(statustip)
        AntiInterference->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\273\272\350\256\256\345\213\276\351\200\211", nullptr));
#endif // QT_CONFIG(statustip)
        AntiInterference->setText(QCoreApplication::translate("XinyiVmmClass", "\346\212\227\345\271\262\346\211\260", nullptr));
#if QT_CONFIG(statustip)
        ProtectDebuger->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\273\272\350\256\256\345\213\276\351\200\211", nullptr));
#endif // QT_CONFIG(statustip)
        ProtectDebuger->setText(QCoreApplication::translate("XinyiVmmClass", "\344\277\235\346\212\244\350\260\203\350\257\225\345\231\250", nullptr));
#if QT_CONFIG(statustip)
        Performance->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\273\272\350\256\256\345\213\276\351\200\211", nullptr));
#endif // QT_CONFIG(statustip)
        Performance->setText(QCoreApplication::translate("XinyiVmmClass", "\346\200\247\350\203\275\351\224\257\351\275\277", nullptr));
#if QT_CONFIG(statustip)
        antihardware->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\344\270\200\347\202\271\345\260\217\344\270\234\350\245\277", nullptr));
#endif // QT_CONFIG(statustip)
#if QT_CONFIG(whatsthis)
        antihardware->setWhatsThis(QString());
#endif // QT_CONFIG(whatsthis)
        antihardware->setText(QCoreApplication::translate("XinyiVmmClass", "\345\217\215\347\241\254\344\273\266\346\226\255\347\202\271", nullptr));
#if QT_CONFIG(statustip)
        infbreakpoint->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\274\272\345\210\266\345\274\200\345\220\257", nullptr));
#endif // QT_CONFIG(statustip)
        infbreakpoint->setText(QCoreApplication::translate("XinyiVmmClass", "\346\227\240\347\227\225\347\241\254\346\226\255(\345\274\272\345\210\266)", nullptr));
#if QT_CONFIG(statustip)
        disablethread->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\347\234\213\346\203\205\345\206\265\345\213\276\351\200\211", nullptr));
#endif // QT_CONFIG(statustip)
        disablethread->setText(QCoreApplication::translate("XinyiVmmClass", "\347\246\201\347\272\277\347\250\213\346\266\210\346\201\257", nullptr));
#if QT_CONFIG(statustip)
        supercontext->setStatusTip(QCoreApplication::translate("XinyiVmmClass", "\345\217\252\351\200\202\347\224\250\344\272\216ce\345\222\214x64\350\277\233\347\250\213", nullptr));
#endif // QT_CONFIG(statustip)
        supercontext->setText(QCoreApplication::translate("XinyiVmmClass", "\344\270\212\344\270\213\346\226\207\346\250\241\345\274\217", nullptr));
    } // retranslateUi

};

namespace Ui {
    class XinyiVmmClass: public Ui_XinyiVmmClass {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_XINYIVMM_H
