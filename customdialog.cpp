#include "customdialog.h"
#include "ui_customdialog.h"

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

void CustomDialog::setText(QString text)
{
    ui->dialogBrowser->setHtml(text);
}

void CustomDialog::on_pushButton_clicked()
{
    this->close();
}
