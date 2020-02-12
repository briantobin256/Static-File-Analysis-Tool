#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QTextBrowser>
#include <QDebug>
#include <QFileDialog>
#include <iostream>
#include <fstream>
#include <QWheelEvent>
#include <QVBoxLayout>
#include <QCheckBox>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    char *rawData;

    QString basicWindowName;
    QString extendedWindowName;
    QString fileName;
    QString fileHash;
    QStringList strings;

    QMap<int, bool> savedStringMap;

    int stringCount;
    int stringOffset;
    int maxDisplayStrings;
    int stringsAdvancedSearchIterator;
    QString stringsAdvancedSearchString;

    bool fileOpened;
    int fileSize;

    bool backupBuilt;
    bool hashBuilt;
    bool packChecked;
    bool packPacked;
    bool packUnpacked;
    bool stringsBuilt;
    bool stringsDisplayed;
    bool stringsSaved;
    bool hexBuilt;
    bool dllsBuilt;
    bool checklistBuilt;

private slots:
    void on_actionCheck_if_Packed_triggered();

    void on_actionGenerate_Hash_triggered();

    void on_actionCreate_Backup_triggered();

    void on_actionPack_triggered();

    void on_actionUnpack_triggered();

    void on_actionFind_Strings_triggered();

    void on_actionChecklistMain_triggered();

    void on_actionSaved_Strings_triggered();

    void on_actionHex_triggered();

    void on_actionOpen_triggered();

    void on_actionDisassembly_triggered();

    void on_hexScrollBar_valueChanged();

    void on_actionDLL_s_triggered();

    void on_stringsScrollBar_valueChanged();

    void on_actionSeperate_Window_triggered();

    void on_stringSearchButton_clicked();

private:
    Ui::MainWindow *ui;
    bool isPacked();
    void refreshHex();
    void findStrings();
    void refreshStrings();
    void refreshSavedStrings();
    void saveDisplayedStrings();
    void findDLLs();
    void refreshChecklist();
    void refreshWindow();
    virtual void wheelEvent(QWheelEvent *event);
};
#endif // MAINWINDOW_H
