#include "XinyiVmm.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    XinyiVmm w;
    w.show();
    return a.exec();
}
