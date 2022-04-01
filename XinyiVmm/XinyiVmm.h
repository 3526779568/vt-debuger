#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_XinyiVmm.h"
#include "User.h"

class XinyiVmm : public QMainWindow
{
    Q_OBJECT

public:
    XinyiVmm(QWidget *parent = Q_NULLPTR);
    void RunDebuger(int id);

private:
    Ui::XinyiVmmClass ui;
    User *user;
    QString hdinfo;
public slots:
  void LoginClicked();
  void Open1Clicked();
  void Open2Clicked();
  void Open3Clicked();
  void Open4Clicked();
  void ClickConf();
};
