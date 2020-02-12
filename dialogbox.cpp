#include "dialogbox.h"
#include "ui_dialogbox.h"

DialogBox::DialogBox(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogBox)
{
    ui->setupUi(this);
}

DialogBox::~DialogBox()
{
    delete ui;
}

void DialogBox::on_pushButton_clicked()
{
    this->close();
}
