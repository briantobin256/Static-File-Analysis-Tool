#include "customdialog.h"
#include "ui_dialogbox.h"

CustomDialog::CustomDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogBox)
{
    ui->setupUi(this);
}

CustomDialog::~CustomDialog()
{
    delete ui;
}

void CustomDialog::on_pushButton_clicked()
{
    this->close();
}
