#ifndef DIALOGBOX_H
#define DIALOGBOX_H

#include <QDialog>

namespace Ui {
class DialogBox;
}

class CustomDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CustomDialog(QWidget *parent = nullptr);
    ~CustomDialog();
    void setText(QString text);

private slots:
    void on_pushButton_clicked();

private:
    Ui::DialogBox *ui;
};

#endif // DIALOGBOX_H
