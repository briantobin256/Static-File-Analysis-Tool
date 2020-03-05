#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include "customdialog.h"
#include <QTextBrowser>
#include <QDebug>
#include <QFileDialog>
#include <iostream>
#include <fstream>
#include <QWheelEvent>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QTableWidgetItem>
#include <QListWidgetItem>
#include <QClipboard>
#include <QMessageBox>
#include <QCoreApplication>
#include <QCloseEvent>
#include <math.h>
#include <QtCharts>

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
    QString directory;
    QString fileHash;
    QStringList strings;
    QStringList unsortedStrings;
    QString backupLoc;

    // string things
    QMap<QString, bool> stringsMap;
    QMap<int, bool> savedStringMap;
    QMap<int, int> savedStringLocationMap;
    QMap<int, int> hexLocationMap;
    QMap<int, int> swapStringMap;

    int stringCount;
    int stringOffset;
    int maxDisplayStrings;
    int stringsAdvancedSearchIndex;
    int dllSearchIndex;
    QString stringsAdvancedSearchString;
    bool sortStrings;
    bool removeDuplicates;
    int stringLength;
    bool sorting;
    bool removedStrings;


    bool fileOpened;
    int fileSize;

    double entropy;

    //hex things
    int dataStartPoint;
    int maxRows;
    int maxCols;
    int displayRows;
    int displayCols;
    bool dataChanged;
    QMap<int, char> originalDataMap;
    QMap<int, bool> changedDataMap;

    bool stringsSorted;
    bool backupBuilt;
    bool firstStringsRefresh;
    bool hashBuilt;
    bool packChecked;
    bool packed;
    bool packPacked;
    bool packUnpacked;
    bool stringsBuilt;
    bool stringsDisplayed;
    bool stringsSaved;
    bool hexBuilt;
    bool dllsBuilt;
    bool checklistBuilt;
    bool entropyChecked;
    bool entropyGraphBuilt;


    // disassembly
    bool disassemblyBuilt;
    int codeStart;
    //int disassemblyOffset;
    QMap<int, QString>opcodeMap;

    bool reseting;

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

    void on_hexScrollBar_valueChanged();

    void on_actionDLL_s_triggered();

    void on_stringsScrollBar_valueChanged();

    void on_actionSeperate_Window_triggered();

    void on_stringSearchButton_clicked();

    void on_savedStringList_itemDoubleClicked(QListWidgetItem *item);

    void on_hexTable_itemChanged(QTableWidgetItem *item);

    void on_actionUndo_All_Changes_triggered();

    void on_actionExit_triggered();

    void on_actionSave_triggered();

    void on_stringList_itemDoubleClicked(QListWidgetItem *item);

    void on_stringSortUnsort_clicked();

    void on_deleteSelectedStringsButton_clicked();

    void on_actionEntropy_Graph_triggered();

    void on_actionDisassembly_triggered();

private:
    Ui::MainWindow *ui;
    CustomDialog *dialogBox;
    QString generateHash(char *data, int size);
    QString generateFileHash(QString fileName);
    void open(QFile *f);
    bool isPacked();
    bool pack();
    bool unpack();
    void refreshHex();
    void findStrings();
    void refreshStrings();
    void refreshSavedStrings();
    void saveDisplayedStrings();
    void findDLLs();
    void refreshChecklist();
    void refreshWindow();
    void resetChecks();
    void saveChanges();
    void undoChanges();
    void MainWindow::closeEvent (QCloseEvent *event);
    void getEntropy();
    double chunkEntropy(int offset, int chunkSize);
    void buildEntropyGraph();
    void stringToHexLocation(QListWidgetItem *item);
    void removeSelected();
    void refreshDisassembly();

    //void searchStringList;


    virtual void wheelEvent(QWheelEvent *event);
};
#endif // MAINWINDOW_H
