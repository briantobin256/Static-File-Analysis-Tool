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
    bool fileOpened;
    int fileSize;
    bool checklistOpened;


    QString basicWindowName;
    QString extendedWindowName;
    QString fileName;
    QString directory;
    QString fileHash;
    QString backupLoc;


    // string things
    QMap<int, QString> stringLocationMap;
    QMap<int, bool> savedStringMap;
    QMap<int, int> savedStringLocationMap;
    QMap<int, int> hexLocationMap;
    QMap<int, int> swapStringMap;
    QStringList strings;
    QStringList savedStrings;
    QStringList unsortedStrings;
    QString previousSearchString;
    int stringCount;
    int stringOffset;
    int maxDisplayStrings;
    int totalStringSize;
    int totalSavedStringSize;
    int searchStringIndex;
    int stringLength;
    bool sorting;
    bool removedStrings;
    bool stringsSorted;
    bool firstStringsRefresh;


    // DLL things
    QString dllNames;
    QStringList dllFunctionNames;
    QString DLLTitle;
    QString FunctionTitle;


    //hex things
    int hexDisplayRows;
    int hexDisplayCols;
    int previousPosition;
    int byteDisplaySize;
    int cursorLocation;
    bool nextPage;
    bool secondTime;
    bool editing;
    bool refreshing;
    bool dataChanged;
    QMap<int, char> originalDataMap;
    QMap<int, bool> changedDataMap;


    // initial builds
    bool packChecked;
    bool packed;
    bool packPacked;
    bool stringsBuilt;
    bool stringsDisplayed;
    bool dllsBuilt;
    bool entropyGraphBuilt;


    // PE things
    bool PE;
    int imagebase;
    int codeStartLoc, codeEndLoc, codeVirtualAddress;
    int rdataStartLoc, rdataRVA;
    int idataStartLoc, idataRVA;
    int IDTLoc, IDTSize;
    int IATLoc, IATSize;
    int codeEntryPoint, baseOfCode;
    int dataStartLoc, dataVirtualAddress;


    // disassembly
    bool disassemblyBuilt;
    int maxDisplayInstructions;
    QStringList disassembly;
    QMap<int, int>opTypeMap;
    QMap<int, QString>opcodeMap;
    QMap<QString, int> locOffsetMap;
    int codeStartProcedure;
    QStack<int> jumpStack;

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

    void on_actionUndo_All_Changes_triggered();

    void on_actionExit_triggered();

    void on_actionSave_triggered();

    void on_stringList_itemDoubleClicked(QListWidgetItem *item);

    void on_actionEntropy_Graph_triggered();

    void on_actionDisassembly_triggered();

    void on_disassemblyScrollBar_valueChanged();

    void on_disassemblyBrowser_anchorClicked(const QUrl &arg1);

    void on_hexByteDisplay_cursorPositionChanged();

    void on_hexByteDisplay_textChanged();

    void showContextMenu(const QPoint &point);

    void copyHighlightedItemsText();

    void checkHighlighted();

    void uncheckHighlighted();

    void removeSelected();

    void highlightAll();

    void sortStrings();

    void outputStrings();

    void stringToHexLocation();

    void on_savedStringSearchButton_clicked();

    void on_DLLTitleBrowser_anchorClicked(const QUrl &arg1);

    void on_DLLFunctionTitleBrowser_anchorClicked(const QUrl &arg1);

    void on_disassemblyStartLocationButton_clicked();

    void on_disassemblySearchButton_clicked();

    void on_disassemblyJumpBackButton_clicked();

private:
    Ui::MainWindow *ui;
    CustomDialog *dialogBox;

    // general ui things
    void refreshWindow();
    void resetChecks();
    void MainWindow::closeEvent();
    virtual void wheelEvent(QWheelEvent *event);
    void showChecklist();
    void hideChecklist();
    void popChecklist();
    void buildChecklist();

    // hashing
    QString generateHash(char *data, int size);
    QString generateFileHash(QString fileName);

    // file
    void open(QFile *f);
    void saveChanges();
    void undoChanges();
    void getPEinformation();

    // packing
    bool isPacked();
    bool pack();
    bool unpack();
    double getEntropy();
    void buildEntropyGraph();
    double chunkEntropy(int offset, int chunkSize);

    // strings
    void findStrings();
    void saveDisplayedStrings();
    void refreshStrings();
    void refreshSavedStrings();
    bool searchStringList(QString searchString, QStringList *list, bool searchFromBeginning, bool htmlList);
    QString htmlSanitiseString(QString string);

    // dlls
    void findDLLs();
    QString getFunctionName(int location, int dataSectionRVA, int dataStartLoc);

    // hex
    void refreshHex();
    QString byteToHexString(int c);
    void setHexValues();
    void moveCursor(int direction);


    // disassembly
    void getDisassembly();
    QStringList disassembleSection(int start, int end, int virtualAddress);
    void refreshDisassembly();
    QString registerName(int reg, int operandSize);
    QString segmentRegisterName(int reg);
    QString getSpecialByteInstruction(int specialByte, int reg);
    QString getExtendedByteInstruction(int extendedByte, int reg);
    int getOperandSize(unsigned char byte, bool operandSizeModifier);
    QString immediateFormat(QString s);
    QString getFunctionCallName(int immediateValue);
    QString immediateIsStringOffset(int immediateValue, int physicalAddress, int virtualAddress);

    //void searchStringList;
};
#endif // MAINWINDOW_H
