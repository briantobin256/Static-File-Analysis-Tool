#include "customdialog.h"
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(0);

    basicWindowName = "Static File Analysis Tool";

    fileOpened = false;
    resetChecks();

    hashBuilt = false;
    fileHash = "";
    backupLoc = "";

    refreshWindow();
}

MainWindow::~MainWindow()
{
    delete ui;
}

// UI ACTIONS

void MainWindow::on_actionOpen_triggered()
{
    saveChanges();
    QFile file(QFileDialog::getOpenFileName(this, "Select a file to analyse", "D:/Downloads"));
    open(&file);
    file.close();
}

void MainWindow::on_actionSave_triggered()
{
    saveChanges();
}

void MainWindow::on_actionUndo_All_Changes_triggered()
{
    undoChanges();
    refreshWindow();
}

void MainWindow::on_actionGenerate_Hash_triggered()
{
    saveChanges();
    dialogBox = new CustomDialog();
    dialogBox->setWindowTitle("Hash");
    QLabel *label = new QLabel(dialogBox);

    if (fileOpened) {
        fileHash = generateHash(rawData, fileSize);
        label->setText("The SHA-1 hash of the current data is:\n" + fileHash);
    }
    else {
        label->setText("No file is selected.");
    }

    hashBuilt = true;
    dialogBox->exec();
    refreshWindow();
}

void MainWindow::on_actionCreate_Backup_triggered()
{
    saveChanges();
    dialogBox = new CustomDialog();
    dialogBox->setWindowTitle("Backup");
    QLabel *label = new QLabel(dialogBox);

    if (fileOpened) {
        QDir dir;
        label->setText("Please select a location to store backups.");
        dialogBox->exec();
        QFile file(QFileDialog::getExistingDirectory(this, "Select a location to store backups."));
        backupLoc = file.fileName();
        dir.setPath(backupLoc);
        file.close();

        if (backupLoc != "") {

            fileHash = generateHash(rawData, fileSize);

            // check if file exists with current backup name
            QString backupName = fileHash + ".bak";
            bool backupConflict = false;
            int i = 0;
            QFileInfoList list = dir.entryInfoList();
            while (!backupConflict && i < list.size()) {
                QFileInfo fileInfo = list.at(i);
                if (backupName == fileInfo.fileName()) {
                    backupConflict = true;
                }
                i++;
            }

            if (backupConflict) {
                if (backupName == fileName) {
                    label->setText("The current file is the backup file. Rename it to back it up again.");
                }
                else {
                    label->setText("A backup of this file already exists.");
                }
            }
            else {
                // create backup
                QString fullName = backupLoc + 92 + backupName;
                QFile createBackup(fullName);

                if (createBackup.open(QIODevice::ReadWrite)) {
                    QDataStream ds(&createBackup);
                    ds.writeRawData(rawData, fileSize);
                    createBackup.close();
                }

                // create verficication hash
                QString verificationHash = generateFileHash(fullName);

                if (verificationHash == fileHash) {
                    label->setText("Backup Succesful.\n" + fileName + "\nhas been saved as\n" + fileHash + ".bak");
                }
                else {
                    label->setText("An error has occured, the backup may not exist.");
                }
            }
            backupBuilt = true;
        }
        else {
            label->setText("No location selected.");
        }
        dialogBox->exec();
    }
    else {
        label->setText("You must first select a file to analyse before anything can be backed up.");
        dialogBox->exec();
    }

    refreshWindow();
}

void MainWindow::on_actionExit_triggered()
{
    saveChanges();
    QApplication::quit();
}

void MainWindow::on_actionCheck_if_Packed_triggered()
{
    saveChanges();
    dialogBox = new CustomDialog();
    dialogBox->setWindowTitle("Check if File is Packed");
    QLabel *label = new QLabel(dialogBox);

    if (fileOpened) {
        getEntropy();
        if (isPacked()) {
            label->setText("The current file IS packed using UPX.");
        }
        else {

            QString basicText = "The current file is NOT packed using UPX!";
            QString entropyVar;
            if (entropy < 7) {
                entropyVar = "The files entropy is \n" + QString::number(entropy) + "\nwhich would suggest that the file is NOT packed/compressed/encrypted.";
            }
            else {
                entropyVar = "The files entropy is \n" + QString::number(entropy) + "\nwhich would suggest that the file IS packed/compressed/encrypted.";
            }

            entropyVar += "\nCheck the entropy graph for more in depth detail of the total file entropy.";
            label->setText(basicText + entropyVar);
        }
    }
    else {
        label->setText("No file is selected.");
    }

    dialogBox->exec();
    packChecked = true;
    refreshWindow();
}

void MainWindow::on_actionEntropy_Graph_triggered()
{
    ui->stackedWidget->setCurrentIndex(5);
    buildEntropyGraph();
    refreshWindow();
}

void MainWindow::on_actionPack_triggered()
{
    saveChanges();
    dialogBox = new CustomDialog();
    dialogBox->setWindowTitle("Pack");
    QLabel *label = new QLabel(dialogBox);

    if (fileOpened) {
        if (isPacked()) {
            label->setText("The current file is already packed using UPX.");
        }
        else {
            // pack the current file
            if (pack()) {
                packChecked = false;
                if (isPacked()) {
                    label->setText("The current file is now packed using UPX.");
                    packPacked = true;
                    packUnpacked = false;

                    // open newly packed file to analyse
                    QFile file(directory + fileName);
                    open(&file);
                    file.close();
                }
                else {
                    label->setText("The current file was not packed using UPX.");
                }
            }
            else {
                label->setText("The current file was not packed using UPX.");
            }
        }
    }
    else {
        label->setText("No file is selected.");
    }

    dialogBox->exec();
    refreshWindow();
}

void MainWindow::on_actionUnpack_triggered()
{
    saveChanges();
    dialogBox = new CustomDialog();
    dialogBox->setWindowTitle("Unpack");
    QLabel *label = new QLabel(dialogBox);

    if (fileOpened) {
        if (isPacked()) {
            // unpack the current file
            if (unpack()) {
                label->setText("The current file has been unpacked using UPX.");
                packChecked = false;
                packUnpacked = true;
                packPacked = false;

                // open newly packed file to analyse
                QFile file(directory + fileName);
                open(&file);
                file.close();
            }
            else {
                label->setText("The current file was not unpacked.");
            }
        }
        else {
            label->setText("The current file is not packed using UPX.");
        }
    }
    else {
        label->setText("No file is selected.");
    }

    dialogBox->exec();
    refreshWindow();
}

void MainWindow::on_actionFind_Strings_triggered()
{
    ui->stackedWidget->setCurrentIndex(1);
    refreshWindow();
}

void MainWindow::on_actionSaved_Strings_triggered()
{
    ui->stackedWidget->setCurrentIndex(2);
    refreshWindow();

}

void MainWindow::on_actionDLL_s_triggered()
{
    ui->stackedWidget->setCurrentIndex(3);
    refreshWindow();
}

void MainWindow::on_actionHex_triggered()
{
    ui->stackedWidget->setCurrentIndex(4);
    refreshWindow();
}

void MainWindow::on_actionChecklistMain_triggered()
{
    ui->stackedWidget->setCurrentIndex(6);
    refreshWindow();
}

void MainWindow::on_actionSeperate_Window_triggered()
{
    //ui->stackedWidget->setCurrentIndex(8);
    refreshWindow();
}

void MainWindow::on_actionDisassembly_triggered()
{
    ui->stackedWidget->setCurrentIndex(7);
    refreshWindow();
}

void MainWindow::on_stringsScrollBar_valueChanged()
{
    if (!reseting) {
        refreshStrings();
    }
}

void MainWindow::on_hexScrollBar_valueChanged()
{
    if (!reseting) {
        refreshHex();
    }
}

void MainWindow::on_stringList_itemDoubleClicked(QListWidgetItem *item)
{
    stringToHexLocation(item);
}

void MainWindow::on_savedStringList_itemDoubleClicked(QListWidgetItem *item)
{
    //QApplication::clipboard()->setText(item->text());
    stringToHexLocation(item);
}

void MainWindow::on_hexTable_itemChanged(QTableWidgetItem *item)
{
    if (fileOpened) {
        int row =  item->row(), col =  item->column();

        // check if cell is within displayrows and displaycols
        if (row < maxRows && col < maxCols) {
            bool inScope = true;
            // if out of current file scope
            if (ui->hexScrollBar->value() == ui->hexScrollBar->maximum()) {
                if (row >= displayRows) {
                    inScope = false;
                }
                else if (row == displayRows - 1) {
                    if (col >= displayCols) {
                        inScope = false;
                    }
                }
            }

            if(inScope) {
                ui->hexTable->blockSignals(true);
                QTableWidgetItem *hex;
                QString hexText = "00";
                QString text = item->text();

                // check if entered value is valid
                bool good = true;
                if (text.size() == 1 || text.size() == 2) {
                    for (int i = 0; i < text.size(); i++) {
                        // if number or upper case char
                        if ((text[i].unicode() >= 48 && text[i].unicode() <= 57) || (text[i].unicode() >= 65 && text[i].unicode() <= 70)) {
                            if (text.size() == 1) {
                                hexText[1] = text[i];
                            }
                            else {
                                hexText[i] = text[i];
                            }
                        }
                        // if lower case char
                        else if (text[i].unicode() >= 97 && text[i].unicode() <= 102) {
                            if (text.size() == 1) {
                                hexText[1] = text[0].unicode() - 32;
                            }
                            else {
                                hexText[i] = text[i].unicode() - 32;
                            }
                        }
                        else {
                            good = false;
                        }
                    }
                }
                else {
                    good = false;
                }

                if (!good) {
                    char c = rawData[(dataStartPoint * maxCols) + col + (row * maxCols)];
                    unsigned char uc = static_cast<unsigned char>(c);
                    // convert char to hex
                    int temp, i = 1;
                    while(uc != 0) {
                        temp = uc % 16;
                        // to convert integer into character
                        if(temp < 10)
                        {
                            temp += 48;
                        }
                        else
                        {
                            temp += 55;
                        }
                        hexText[i] = temp;
                        i--;
                        uc = uc / 16;
                    }
                }

                hex = new QTableWidgetItem(hexText);
                hex->setTextAlignment(Qt::AlignCenter);
                ui->hexTable->setItem(row, col, hex);

                // hex to dec
                int charDec1 = hexText[0].unicode(), charDec2 = hexText[1].unicode();
                if (charDec1 > 57) {
                    charDec1 = charDec1 - 55;
                }
                else {
                    charDec1 = charDec1 - 48;
                }
                if (charDec2 > 57) {
                    charDec2 = charDec2 - 55;
                }
                else {
                    charDec2 = charDec2 - 48;
                }
                int fullDec = charDec1 * 16 + charDec2;

                int location = (dataStartPoint * maxCols) + col + (row * maxCols);
                if (!changedDataMap[location]) {
                    originalDataMap[location] = rawData[location];
                    changedDataMap[location] = true;
                }

                rawData[location] = fullDec;
                dataChanged = true;
            }
            else {
                ui->hexTable->clearContents();
            }
        }
        else {
            ui->hexTable->clearContents();
        }
    }
    else {
        ui->hexTable->clearContents();
    }
    refreshHex();
}

void MainWindow::on_stringSearchButton_clicked()
{
    if (stringsBuilt) {

        QString search = ui->searchString->text();

        if (stringsAdvancedSearchString != search) {
            stringsAdvancedSearchIndex = 0;
        }
        stringsAdvancedSearchString = search;

        bool found = false;
        while (!found && stringsAdvancedSearchIndex < stringCount) {

            //
            // starting search icon
            //

            QString searching = strings[stringsAdvancedSearchIndex];
            int searchLength = search.length();
            int searchedLength = strings[stringsAdvancedSearchIndex].length();

            // for each starting position the search string could fit into the searched string
            for (int j = 0; j <= searchedLength - searchLength; j++) {
                int k;
                // for the length of the search string
                for (k = 0; k < searchLength; k++) {
                    // if chars dont match
                    if (searching[j + k] != search[k]) {
                        // if case sensitive match
                        if ((searching[j + k].unicode() + 32) != search[k] && (searching[j + k].unicode() - 32) != search[k]) {
                            break;
                        }
                    }
                }
                if (k == searchLength) {
                    found = true;
                }
            }
            stringsAdvancedSearchIndex++;
        }

        //
        // finished search icon
        //

        if (found) {
            if (stringsAdvancedSearchIndex % maxDisplayStrings == 0) {
                ui->stringsScrollBar->setValue((stringsAdvancedSearchIndex / maxDisplayStrings) - 1);
            }
            else {
                ui->stringsScrollBar->setValue(stringsAdvancedSearchIndex / maxDisplayStrings);
            }
            // highlight string
            //qDebug() << "search string: " << stringsAdvancedSearchIterator;
            //qDebug() << "search string: " << strings[stringsAdvancedSearchIterator - 1];
            //ui->stringList->item((stringsAdvancedSearchIterator % maxDisplayStrings - 1 + maxDisplayStrings) % maxDisplayStrings)->setSelected(true);
            ui->stringList->item((stringsAdvancedSearchIndex % maxDisplayStrings - 1 + maxDisplayStrings) % maxDisplayStrings)->setCheckState(Qt::Checked);
            //ui->stringList->setFocus();
            refreshStrings();
        }
        else if (stringsAdvancedSearchIndex == stringCount) {
            stringsAdvancedSearchIndex = 0;
        }
    }
}

void MainWindow::on_stringSortUnsort_clicked()
{
    saveDisplayedStrings();
    sorting = true;
    if (stringsSorted) { // unsort
        for (int i = 0; i < stringCount; i++) {
            swapStringMap[i] = i;
        }
        strings = unsortedStrings;
        stringsSorted = false;
    }
    else { // sort
        for (int i = 0; i < stringCount; i++) {
            strings[i] += "(" + QString::number(i);
        }
        strings.sort();
        for (int i = 0; i < stringCount; i++) {
            QString string = strings[i];
            int startOfOldLoc = string.lastIndexOf("(", string.size() - 1);
            int oldLoc = string.mid(startOfOldLoc + 1, string.size() - 1).toInt();
            strings[i] = string.mid(0, startOfOldLoc);
            swapStringMap[oldLoc] = i;
        }
        stringsSorted = true;
    }

    QMap<int, bool> tmpSavedSwapMap;
    for (int i = 0; i < stringCount; i++) {
        tmpSavedSwapMap[swapStringMap[i]] = savedStringMap[i];
    }
    savedStringMap = tmpSavedSwapMap;

    refreshWindow();
}

void MainWindow::on_deleteSelectedStringsButton_clicked()
{
    removeSelected();
    refreshWindow();
}

void MainWindow::wheelEvent(QWheelEvent *event)
{
    /*
    // only while showing hex
    if (ui->stackedWidget->currentIndex() == 4 && ui->hexScrollBar->maximum() > 0) {

        QPoint numDegrees = event->angleDelta() / 8;

        if (!numDegrees.isNull()) {
            QPoint numSteps = numDegrees / 15;
            int move = static_cast<int>(numSteps.y());
            qDebug() << "move" << move;
            int currentValue = ui->hexScrollBar->value();
            int min = ui->hexScrollBar->minimum();
            int max = ui->hexScrollBar->maximum();

            if (move == 1 && currentValue < max) {
                ui->hexScrollBar ++;
                qDebug() << "moved down";
            }
            else if (move == -1 && currentValue > min) {
                ui->hexScrollBar --;
                qDebug() << "moved up";
            }
        }

        //event->accept();

        //refreshHex();
    }
    */
}

void MainWindow::closeEvent (QCloseEvent *event)
{
    saveChanges();
    QApplication::quit();
}

// BACKGROUND FUNCTIONS

void MainWindow::open(QFile *file)
{
    if (file->fileName() != "") {

        if (file->size() <= 2147483647) {

            bool openFile = true;
            if (file->size() > 1048576) {
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Warning!", "The file you choose is over 1MB.\nIt will be noticiably slower for most of the functions and things may not work as intended.\nAre you sure you want to continue?", QMessageBox::Yes|QMessageBox::No);
                if (reply == QMessageBox::Yes) {
                    openFile = true;
                }
                else {
                    openFile = false;
                }
            }

            if (file->open(QIODevice::ReadOnly) && openFile) {

                if (fileOpened) {
                    free(rawData);
                }

                QDataStream ds(file);
                fileSize = file->size();

                bool enoughMemory = true;
                try {
                    rawData = new char[fileSize];
                } catch (...) {
                    enoughMemory = false;
                }

                if (enoughMemory) {
                    ds.readRawData(rawData, fileSize);
                    fileOpened = true;
                    resetChecks();

                    // get file name and directory
                    QString fullFileName = file->fileName();
                    bool slashFound = false;
                    int i = fullFileName.size() - 1;

                    while (!slashFound && i >= 0) {
                        if (fullFileName[i] == 47 || fullFileName[i] == 92) {
                            slashFound = true;
                        }
                        else {
                            i--;
                        }
                    }

                    if (slashFound) {
                        fileName = fullFileName.mid(i + 1, fullFileName.size() - i);
                        directory = fullFileName.mid(0, i + 1);
                    }
                    basicWindowName = "Static File Analysis Tool - " + fileName;
                }
                else {
                    // display not enough memory
                    dialogBox = new CustomDialog();
                    dialogBox->setWindowTitle("Error");
                    QLabel *label = new QLabel(dialogBox);
                    label->setText("The file you choose is too big.\nThis system does not currently have enough memory to open this file.");
                    dialogBox->exec();
                }
            }
            resetChecks();
            refreshWindow();
        }
        else {
            // file too big
            dialogBox = new CustomDialog();
            dialogBox->setWindowTitle("Error");
            QLabel *label = new QLabel(dialogBox);
            label->setText("The file you choose is too big.\nMax file size of 2GB.");
            dialogBox->exec();
        }
    }
}

QString MainWindow::generateHash(char *data , int size)
{
    QCryptographicHash hash(QCryptographicHash::Sha1);
    hash.addData(data, size);
    return hash.result().toHex().toUpper();
}

QString MainWindow::generateFileHash(QString fullName)
{
    QFile file(fullName);
    QString hashString;
    if (file.open(QIODevice::ReadOnly)) {
        QCryptographicHash hash(QCryptographicHash::Sha1);
        hash.addData(&file);
        hashString = hash.result().toHex().toUpper();
        file.close();
    }
    return hashString;
}

bool MainWindow::isPacked()
{
    if (!packChecked) {

        QString fullFileName = 34 + directory + fileName + 34;
        QString command = "upx -l " + fullFileName + " > upx.tmp";
        system(qPrintable(command));

        // check output
        QFile upxCheck("upx.tmp");
        if (upxCheck.open(QIODevice::ReadOnly)) {
            QTextStream in(&upxCheck);
            int i = 0;
            while (!in.atEnd()) {
                in.readLine();
                i++;
            }
            upxCheck.close();
            if (i == 7) {
                packed = true;
            }
            else {
                packed = false;
            }
        }
        // remove tmp file
        QDir path;
        path.setPath(path.currentPath());
        path.remove("upx.tmp");
        packChecked = true;
    }
    return packed;
}

bool MainWindow::pack()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Warning!", "Make sure to backup the file before packing!/nAre you sure you want to pack the current file?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        QString fullFileName = 34 + directory + fileName + 34;
        QString command = "upx -5 " + fullFileName;
        system(qPrintable(command));
        return true;
    }
    return false;
}

bool MainWindow::unpack()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Warning!", "Make sure to backup the file before unpacking!/nAre you sure you want to unpack the current file?", QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        QString fullFileName = 34 + directory + fileName + 34;
        QString command = "upx -d " + fullFileName;
        system(qPrintable(command));
        return true;
    }
    return false;
}

void MainWindow::findStrings()
{
    if (!stringsBuilt && fileOpened) {
        QString item = "";
        bool nullSpaced = false, validString = false;
        stringCount = 0;

        // for each char in file
        int stringStartLoc = 0;
        for (int i = 0; i < fileSize; i++) {

            if (item == "") {
                stringStartLoc = i;
            }

            // get char
            char c = rawData[i];
            unsigned char uc = static_cast<unsigned char>(c);

            // check if (unsigned) char is printable
            // if char is between 'space' and '~' on the ascii table or char is horizontal tab
            if ((uc >= 32 && uc <= 126)) {
                item += c;
            }
            else {
                // if item has value and current char is null and last value is not null
                if (uc == 0) {
                    // check if this may be a null spaced string
                    if (item.size() == 1 && i + 3 < fileSize) {
                        char tmpc1 = rawData[i + 1], tmpc2 = rawData[i + 2], tmpc3 = rawData[i + 3];
                        unsigned char tmpuc1 = static_cast<unsigned char>(tmpc1);
                        unsigned char tmpuc2 = static_cast<unsigned char>(tmpc2);
                        unsigned char tmpuc3 = static_cast<unsigned char>(tmpc3);
                        if ((tmpuc1 >= 32 && tmpuc1 <= 126) && (tmpuc2 == 0) && (tmpuc3 >= 32 && tmpuc3 <= 126)) {
                                nullSpaced = true;
                        }
                        else {
                            item = "";
                        }
                    }
                    // if nullspaced, check if next char is null and if next two chars are printable
                    else if (nullSpaced) {
                        if (i + 2 < fileSize) {
                            char tmpc1 = rawData[i + 1], tmpc2 = rawData[i + 2];
                            unsigned char tmpuc1 = static_cast<unsigned char>(tmpc1), tmpuc2 = static_cast<unsigned char>(tmpc2);
                            if (tmpuc1 == 0 || ((tmpuc1 >= 32 && tmpuc1 <= 126) && (tmpuc2 >= 32 && tmpuc2 <= 126))) {
                                nullSpaced = false;
                                if (item.size() >= stringLength) {
                                    validString = true;
                                }
                            }
                        }
                    }
                    else if (item.size() >= stringLength) {
                        validString = true;
                    }
                    else {
                        item = "";
                    }
                }
                else if (item.size() >= stringLength) {
                    validString = true;
                }
                else {
                    item = "";
                }
            }

            // if current item should be added to string list
            if (validString) {
                strings.insert(stringCount,item);
                stringsMap[item] = true;
                hexLocationMap[stringCount] = stringStartLoc;
                stringCount++;
                item = "";
                validString = false;
            }
        }

        if (item != "" && item.size() >= stringLength) {
            strings.insert(stringCount,item);
            stringsMap[item] = true;
            hexLocationMap[stringCount] = fileSize - item.size();
            stringCount++;
        }

        for (int i = 0; i < stringCount; i++) {
            swapStringMap[i] = i;
        }

        unsortedStrings = strings;

        // display things
        stringCount = strings.size();
        QString count = QString::number(stringCount);
        ui->stringCountValue->setText(count);

        stringsBuilt = true;
    }
}

void MainWindow::refreshStrings()
{
    if (fileOpened) {
        saveDisplayedStrings();
        ui->stringList->clear();
        maxDisplayStrings = 24; // eventually based on ui things
        int displayStringCount = maxDisplayStrings;
        stringOffset = ui->stringsScrollBar->value() * maxDisplayStrings;

        if (stringCount % maxDisplayStrings > 0) {
            ui->stringsScrollBar->setMaximum(stringCount / maxDisplayStrings);
        }
        else {
            if (stringCount == 0) {
                ui->stringsScrollBar->setMaximum(0);
            }
            else {
                ui->stringsScrollBar->setMaximum(stringCount / maxDisplayStrings - 1);
            }
        }

        if (ui->stringsScrollBar->value() == ui->stringsScrollBar->maximum()) {
            if (stringCount % maxDisplayStrings > 0) {
                displayStringCount = stringCount % maxDisplayStrings;
            }
            else {
                displayStringCount = 0;
            }
        }

        //build checkboxlist
        QStringList displayStrings;
        for (int i = 0; i < displayStringCount; i++) {
            displayStrings.insert(i, strings[stringOffset + i]);
        }

        ui->stringList->addItems(displayStrings);

        // recheck saved strings
        for(int i = 0; i < displayStringCount; i++) {
            if (savedStringMap[i + stringOffset]) {
                ui->stringList->item(i)->setCheckState(Qt::Checked);
            }
            else {
                ui->stringList->item(i)->setCheckState(Qt::Unchecked);
            }
        }

        // display things
        QString currentPage = QString::number(ui->stringsScrollBar->value() + 1);
        QString maxPage = QString::number(ui->stringsScrollBar->maximum() + 1);
        QString display;
        display.append(currentPage);
        display.append(" / ");
        display.append(maxPage);
        ui->stringsPageNumberValue->setText(display);
        ui->stringCountValue->setText(QString::number(stringCount));
    }
}

void MainWindow::saveDisplayedStrings()
{
    if (!firstStringsRefresh) {
        if (!sorting && !removedStrings) {
            if (ui->stringList->count() > 0) {
                for (int i = 0; i < ui->stringList->count(); i++) {
                    if (ui->stringList->item(i)->checkState()) {
                        savedStringMap[stringOffset + i] = true;
                    }
                    else {
                        savedStringMap[stringOffset + i] = false;
                    }
                }
                firstStringsRefresh = false;
            }
        }
        else {
            sorting = false;
            removedStrings = false;
        }
    }
    else {
        firstStringsRefresh = false;
    }
}

void MainWindow::refreshSavedStrings()
{
    if (stringsBuilt) {
        QStringList savedStrings;
        for (int i = 0; i < stringCount; i++) {
            if (savedStringMap[i]) {
               savedStrings += strings[i];
               savedStringLocationMap[savedStrings.count() - 1] = i;
            }
        }
        ui->savedStringList->clear();
        ui->savedStringList->addItems(savedStrings);

        if (ui->savedStringList->count() > 0) {
            stringsSaved = true;
        }

        // display things
        QString count = QString::number(ui->savedStringList->count());
        ui->savedStringCountValue->setText(count);
    }
}

void MainWindow::findDLLs()
{
    if (fileOpened) {
        if (!stringsBuilt) {
            findStrings();
        }

        if (!dllsBuilt) {
            ui->DLL_List->clear();
            QStringList dlls;
            QStringList dllsFunctions;
            QStringList undocumentedDLLs;

            // for each string found
            for (int i = 0; i < stringCount; i++) {

                // any strings ending in ".dll" or ".DLL"
                QString string = strings[i];
                QStringRef subString(&string, string.length() - 4, 4);

                if (subString == ".dll" || subString == ".DLL") {
                    string = string.toUpper();
                    dlls.append(string);
                }
            }

            dlls.removeDuplicates();

            for (int i = 0; i < dlls.size(); i++) {

                QString dllFunctionsFileName = "DLL Functions/";
                QString dllName = dlls[i], dllFunctionsFile = dllName;
                dllFunctionsFile = dllName.mid(0, dllName.length() - 4);
                dllFunctionsFile.append(".txt");
                dllFunctionsFileName.append(dllFunctionsFile);
                dllsFunctions.append(dllName);
                int dllListSize = dllsFunctions.size();

                QFile file(dllFunctionsFileName);
                if (file.open(QIODevice::ReadOnly)) {
                    QTextStream in(&file);
                    while (!in.atEnd()) {
                        QString functionName = in.readLine();
                        if (stringsMap[functionName]) {
                            dllsFunctions.append("      " + functionName);
                        }
                    }
                    file.close();
                }

                if (dllListSize == dllsFunctions.size()) {
                    undocumentedDLLs += dllsFunctions[dllsFunctions.size() - 1];
                    dllsFunctions.removeLast();
                }
            }

            dllsFunctions += undocumentedDLLs;

            /*

            //
            // change to search for dll using search function
            // if last dll append remaining function calls to kernel32
            //

            // for each string found
            for (int i = 0; i < stringCount; i++) {

                // any strings ending in ".dll" or ".DLL"
                QString string = strings[i];
                QStringRef subString(&string, string.length() - 4, 4);

                // valid imported dll (will be all caps except .dll part)
                if (subString == ".dll") {
                    string = string.mid(0, string.length() - 4);
                    QString tmpString = string;
                    tmpString = tmpString.toUpper();

                    if (string == tmpString || string == "kernel32") {
                        dlls += strings[i];

                        // find this dlls functions
                        bool goodFunction = true;
                        int j = i - 1;
                        if (string == "kernel32" || string == "MSVCRT") {
                            j = i + 1;
                        }

                        while (goodFunction) {
                            QString tmp = strings[j];
                            bool hasUpper = false, hasLower = false;
                            if (((tmp[0] >= 65 && tmp[0] <= 90) || tmp[0] == 95) && strings[j].size() >= 5) {
                                for (int k = 1; k < tmp.size(); k++) {
                                    // have at least on cap and one lower to get rid of some false postitives
                                    if (tmp[k] >= 65 && tmp[k] <= 90) {
                                        hasUpper = true;
                                    }
                                    else if (tmp[k] >= 97 && tmp[k] <= 122) {
                                        hasLower = true;
                                    }
                                    else if (tmp[k] != 95 && (tmp[k] < 48 || tmp[k] > 57)) {
                                        goodFunction = false;
                                    }
                                }

                                if (!hasUpper || !hasLower) {
                                    goodFunction = false;
                                }

                                if (goodFunction) {
                                    QString function = "    ";
                                    function.append(tmp);
                                    dlls += function;
                                }
                            }
                            else {
                                goodFunction = false;
                            }
                            if (string == "kernel32" || string == "MSVCRT") {
                                j++;
                            }
                            else {
                                j--;
                            }
                        }
                    }
                }
            }
            */

            //dlls.removeDuplicates();
            ui->DLL_List->addItems(dllsFunctions);
            dllsBuilt = true;
        }
    }
}

void MainWindow::refreshHex()
{
    if (fileOpened) {
        ui->hexTable->blockSignals(true);
        ui->hexTable->clearContents();

        hexBuilt = true;
        int rowNameLength = 8;
        displayCols = 16; // variable
        displayRows = 16; // variable
        maxCols = 16; // static
        maxRows = 16; // static
        dataStartPoint = ui->hexScrollBar->value();

        // if file is big enough to have a scroll bar
        if (fileSize / (displayRows * displayCols) > 0) {

            // if last row is full with data
            if (fileSize % displayCols == 0) {
                ui->hexScrollBar->setMaximum(fileSize / displayCols - 16);
            }
            else {
                ui->hexScrollBar->setMaximum(fileSize / displayCols - 15);
            }
        }
        else {
            ui->hexScrollBar->setMaximum(0);
            if (fileSize > 0) {
                if (fileSize % displayRows == 0) {
                    displayRows = fileSize / displayRows;
                }
                else {
                    displayRows = fileSize / displayRows + 1;
                }
            }
            else {
                displayRows = 0;
            }
        }

        // display things
        QString currentRow, maxRow, rowText = "";
        currentRow = QString::number(dataStartPoint + 1);
        maxRow = QString::number(ui->hexScrollBar->maximum() + 1);
        ui->hexCurrentRowValue->setText(currentRow);
        ui->hexMaxRowValue->setText(maxRow);

        // for each row
        for (int displayRow = 0; displayRow < displayRows; displayRow++) {

            // rename rows
            QString hexString = QString::number(dataStartPoint + displayRow, 16).toUpper() += "0";
            QString rowName = "";
            int hexStringCharLength = hexString.length();
            int zeroPaddingCount = rowNameLength - hexStringCharLength;

            for (int i = 0; i < zeroPaddingCount; i++) {
                rowName += "0";
            }
            rowName += hexString;

            ui->hexTable->verticalHeaderItem(displayRow)->setText(rowName);

            // put hex into table
            char c;
            unsigned char uc;
            QString hexText;
            rowText = "";
            QTableWidgetItem *hex;

            // if last row
            if (displayRow == displayRows - 1 && dataStartPoint == ui->hexScrollBar->maximum()) {
                if (fileSize % displayCols == 0) {
                    displayCols = fileSize % displayCols + displayCols;
                }
                else {
                    displayCols = fileSize % displayCols;
                }
            }

            // for each column in current row
            for (int col = 0; col < displayCols; col++) {
                c = rawData[(dataStartPoint * maxCols) + col + (displayRow * maxCols)];
                uc = static_cast<unsigned char>(c);

                // append char to decoded text
                if (uc >= 32 && uc < 127) {
                    rowText += c;
                }
                else {
                    rowText += " ";
                }

                // convert char to hex
                int temp, i = 1;
                hexText ="00";
                while(uc != 0) {

                    temp = uc % 16;
                    // to convert integer into character
                    if(temp < 10)
                    {
                        temp += 48;
                    }
                    else
                    {
                        temp += 55;
                    }
                    hexText[i] = temp;
                    i--;
                    uc = uc / 16;
                }

                // insert hex into table
                hex = new QTableWidgetItem(hexText);
                hex->setTextAlignment(Qt::AlignCenter);
                ui->hexTable->setItem(displayRow, col, hex);
            }

            // insert decoded text into table
            hex = new QTableWidgetItem(rowText);
            ui->hexTable->setItem(displayRow, 17, hex);
        }
        ui->hexTable->blockSignals(false);
    }
}

void MainWindow::refreshChecklist()
{
    if (fileOpened) {

        if (!checklistBuilt) {
            ui->checklistFileNameValue->setText(fileName);

            // uncheck all steps
            for (int i = 0; i < ui->checklistMainStepsList->count(); i++) {
                ui->checklistMainStepsList->item(i)->setCheckState(Qt::Unchecked);
            }

            ui->checklistMainStepsList->item(0)->setCheckState(Qt::Checked);
            checklistBuilt = true;
        }

        ui->checklistFileHashValue->setText(fileHash);
        ui->checklistFileSizeValue->setText(QString::number(fileSize));

        // progress bar stuff
        int progress = 1;

        if (hashBuilt) {
            QString oldHash = fileHash;
            fileHash = generateHash(rawData, fileSize);
            ui->checklistFileHashValue->setText(fileHash);

            if (oldHash != fileHash) {
                dialogBox = new CustomDialog();
                dialogBox->setWindowTitle("Warning!");
                QLabel *label = new QLabel(dialogBox);
                QString text = "Filehash has been changed from: " + oldHash + " to: " + fileHash;
                label->setText(text);
                dialogBox->exec();
            }

            ui->checklistMainStepsList->item(1)->setCheckState(Qt::Checked);
            progress++;
        }
        if (backupBuilt) {
            ui->checklistMainStepsList->item(2)->setCheckState(Qt::Checked);
            progress++;
        }
        if (packChecked) {
            ui->checklistMainStepsList->item(3)->setCheckState(Qt::Checked);
            progress++;
        }
        if (packUnpacked) {
            ui->checklistMainStepsList->item(4)->setCheckState(Qt::Checked);
            progress++;
        }
        if (stringsBuilt) {
            ui->checklistMainStepsList->item(5)->setCheckState(Qt::Checked);
            progress++;
        }
        if (stringsSaved) {
            ui->checklistMainStepsList->item(6)->setCheckState(Qt::Checked);
            progress++;
        }
        if (dllsBuilt) {
            ui->checklistMainStepsList->item(7)->setCheckState(Qt::Checked);
            progress++;
        }
        if (hexBuilt) {
            ui->checklistMainStepsList->item(8)->setCheckState(Qt::Checked);
            progress++;
        }
        if (entropyChecked) {
            ui->checklistFileEntropyValue->setText(QString::number(entropy));
            //ui->checklistMainStepsList->item(8)->setCheckState(Qt::Checked);
            //progress++;
        }


        // update progress bar
        int steps = 9;
        int percent = progress * 100 / steps;
        ui->checklistProgressBar->setValue(percent);
    }
}

void MainWindow::refreshWindow()
{
    saveChanges();

    // refresh window based on current page
    switch (ui->stackedWidget->currentIndex()) {

        case 0: extendedWindowName = "";
        break;

        case 1: extendedWindowName = " - Strings";
        findStrings();
        refreshStrings();
        break;

        case 2: extendedWindowName = " - Saved Strings";
        saveDisplayedStrings();
        refreshSavedStrings();
        break;

        case 3: extendedWindowName = " - DLLs";
        findDLLs();
        break;

        case 4: extendedWindowName = " - Hex";
        refreshHex();
        break;

        case 5: extendedWindowName = " - Entropy";
        buildEntropyGraph();
        break;

        case 6: extendedWindowName = " - Checklist";
        refreshChecklist();
        break;

        case 7: extendedWindowName = " - Disassembly";
        refreshDisassembly();
        break;
    }

    // window name
    this->setWindowTitle(basicWindowName + extendedWindowName);
}

void MainWindow::resetChecks()
{
    reseting = true;
    backupBuilt = false;
    packChecked = false;
    packed = false;
    packPacked = false;
    packUnpacked = false;
    dllsBuilt = false;
    hexBuilt = false;
    dataChanged = false;
    checklistBuilt = false;
    entropyChecked = false;

    // strings
    stringsBuilt = false;
    stringsDisplayed = false;
    stringsSaved = false;
    stringsSorted = false;
    firstStringsRefresh = true;
    strings.clear();
    unsortedStrings.clear();
    stringsMap.clear();
    savedStringMap.clear();
    swapStringMap.clear();
    stringLength = 3;
    ui->stringsScrollBar->setValue(0);
    sorting = false;

    hexLocationMap.clear();
    originalDataMap.clear();
    changedDataMap.clear();
    ui->hexScrollBar->setValue(0);
    ui->hexTable->horizontalHeader()->resizeSection(17, 150);
    entropy = 0;
    entropyGraphBuilt = false;

    disassemblyBuilt = false;
    codeStart = 0;

    reseting = false;
}

void MainWindow::undoChanges()
{
    if (dataChanged) {
        for (int i = 0; i < fileSize; i++) {
            if (changedDataMap[i]) {
                rawData[i] = originalDataMap[i];
            }
        }
        dataChanged = false;
    }
}

void MainWindow::saveChanges()
{
    if (dataChanged) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Warning!", "Do you want to save the changes made in the hex editor?", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {

            // change actual file data
            QString tmpHash = generateHash(rawData, fileSize);
            QString tmpName = tmpHash + ".tmp";
            QString fullTmpName = directory + tmpName;
            QFile newFile(fullTmpName);
            if (newFile.open(QIODevice::ReadWrite)) {
                QDataStream ds(&newFile);
                ds.writeRawData(rawData, fileSize);
                newFile.close();
            }

            // create verficication hash
            QString verificationHash = generateFileHash(fullTmpName);

            // verify save
            QDir path(directory);
            if (verificationHash == tmpHash) {
                // delete original file and rename tmp file
                path.remove(fileName);
                path.rename(tmpName, fileName);

                // reset checks
                resetChecks();
            }
            else {
                dialogBox = new CustomDialog();
                dialogBox->setWindowTitle("Error");
                QLabel *label = new QLabel(dialogBox);
                label->setText("An error has occured. No changes have been saved.");
                dialogBox->exec();

                path.remove(tmpName);
                undoChanges();
            }
        } else {
            undoChanges();
        }
        dataChanged = false;
    }
}

void MainWindow::getEntropy()
{
    if (fileOpened) {
        if (!packChecked) {
            if (entropy <= 0) {
                entropy = chunkEntropy(0, fileSize);
                entropyChecked = true;
            }
        }
    }
}

double MainWindow::chunkEntropy(int offset, int chunkSize)
{
    double chunkEntropy = 0;
    if (fileOpened) {
        if (offset + chunkSize > fileSize) {
            chunkSize = ((fileSize - (offset + chunkSize)) + chunkSize) % chunkSize;
        }

        QMap<unsigned char, double> freqMap;

        // set all to 0
        for (int i = 0; i < 256; i++) {
            unsigned char c = i;
            freqMap[c] = 0;
        }

        // get char freq
        for (int i = 0; i < chunkSize; i++) {
            char c = rawData[i + offset];
            unsigned char uc = static_cast<unsigned char>(c);
            freqMap[uc]++;
        }

        // get probabilty of each char and append to entropy
        for (int i = 0; i < 256; i++) {
            unsigned char c = i;
            double prob = freqMap[c] / chunkSize;
            if (prob > 0) {
                chunkEntropy += (-1 * (prob * (log2(prob))));
            }
        }
    }
    return chunkEntropy;
}

void MainWindow::buildEntropyGraph()
{
    if (fileOpened && fileSize > 0) {
        if (!entropyGraphBuilt) {
            int chunks = 64; // max chunks
            int chunkSize = 256;

            // get good chunk size and no. of chunks(max 64)
            bool goodChunkCount = false, goodChunkSize = false;
            while ((!goodChunkSize || !goodChunkCount) && chunks > 0) {
                if (fileSize / chunks > chunkSize && !goodChunkCount) {
                    chunkSize *= 2;
                }
                else {
                    if (chunks * chunkSize > fileSize && !goodChunkSize) {
                        chunks--;
                    }
                    else {
                        goodChunkSize = true;
                    }
                    goodChunkCount = true;
                }
            }

            QBarSet *entropySet = new QBarSet("Chunk Entropy");
            QStringList chunkRange;

            // for all full chunks
            for (int i = 0; i < chunks; i++) {
                *entropySet << chunkEntropy(i * chunkSize, chunkSize);
                chunkRange << QString::number(i); //QString::number(i * chunkSize);// + " - " + QString::number((i * chunkSize) + chunkSize);
            }
            // last and incomplete chunk
            if (fileSize % chunkSize > 0) {
                *entropySet << chunkEntropy(chunks * chunkSize, (fileSize % chunkSize + chunkSize) % chunkSize);
                chunkRange << QString::number(chunks); //QString::number(chunks * chunkSize);// << " - " << QString::number((chunks * chunkSize) + ((fileSize % chunkSize + chunkSize) % chunkSize));
            }

            QBarCategoryAxis *axisY = new QBarCategoryAxis();
            QValueAxis *axisX = new QValueAxis();
            //QValueAxis *axisY = new QValueAxis();
            QHorizontalBarSeries *series = new QHorizontalBarSeries();

            // reverse data for graph output
            QBarSet *tmpSet = new QBarSet("");
            QStringList tmpList;
            for (int i = 0; i < entropySet->count(); i++) {
                *tmpSet << entropySet->at(entropySet->count() - 1 - i);
                tmpList << chunkRange.at(chunkRange.count() - 1 - i);

            }
            entropySet = tmpSet;
            chunkRange = tmpList;

            series->append(entropySet);
            axisY->append(chunkRange);

            QChart *chart = new QChart();
            chart->addSeries(series);

            QString chunkBytes = " bytes";
            if (chunkSize >= 1024) {
                chunkBytes = QString::number(chunkSize / 1024) + " kibibytes";
                if (chunkSize >= 1048576) {
                    chunkBytes = QString::number(chunkSize / 1048576) + " mebibytes";
                    if (chunkSize >= 1073741824) {
                        chunkBytes = QString::number(chunkSize / 1073741824) + " gibibytes";
                    }
                }
            }
            if (fileSize % chunkSize > 0) {
                if (chunks == 0) {
                    chart->setTitle("Average file entropy across " + QString::number(1) + " chunk of " + chunkBytes);
                }
                else {
                    chart->setTitle("Average file entropy across " + QString::number(chunks+1) + " chunks of " + chunkBytes + "  each, with the last being the remaining " + QString::number(fileSize % chunkSize) + " bytes.");
                }

            }
            else {
                chart->setTitle("Average file entropy across " + QString::number(chunks) + " chunks of " + chunkBytes +" each.");
            }

            //chart->addAxis(axisY, Qt::AlignLeft);

            chart->addAxis(axisX, Qt::AlignBottom);
            series->attachAxis(axisX);
            axisX->setMax(8);
            axisX->applyNiceNumbers();

            chart->legend()->setVisible(false);
            //chart->legend()->setAlignment(Qt::AlignBottom);
            //chart->setAnimationOptions(QChart::AllAnimations);

            QChartView *chartView = new QChartView(chart);
            ui->scrollArea->setWidget(chartView);

            entropyGraphBuilt = true;
        }
    }
}

void MainWindow::stringToHexLocation(QListWidgetItem *item)
{
    bool itemIndexFound = false;
    int i = 0;

    // if from find strings
    if (ui->stackedWidget->currentIndex() == 1) {
        ui->stackedWidget->setCurrentIndex(4);
        refreshWindow();
        while (!itemIndexFound && i < maxDisplayStrings) {
            if (ui->stringList->item(i) == item) {
                itemIndexFound = true;
            }
            else {
                i++;
            }
        }
        if (stringsSorted) {
            bool locFound = false;
            int j = 0;
            while (!locFound && j < stringCount) {
                if (swapStringMap[j] == stringOffset + i) {
                    locFound = true;
                }
                else {
                    j++;
                }
            }
            ui->hexScrollBar->setValue(hexLocationMap[j] / maxCols);
        }
        else {
            ui->hexScrollBar->setValue(hexLocationMap[stringOffset + i] / maxCols);
        }
    }
    // if from saved strings
    else if (ui->stackedWidget->currentIndex() == 2) {
        ui->stackedWidget->setCurrentIndex(4);
        refreshWindow();
        while (!itemIndexFound && i < ui->savedStringList->count()) {
            if (ui->savedStringList->item(i) == item) {
                itemIndexFound = true;
            }
            else {
                i++;
            }
        }
        if (stringsSorted) {
            bool locFound = false;
            int j = 0;
            while (!locFound && j < stringCount) {
                if (swapStringMap[j] == savedStringLocationMap[i]) {
                    locFound = true;
                }
                else {
                    j++;
                }
            }
            ui->hexScrollBar->setValue(hexLocationMap[j] / maxCols);
        }
        else {
            ui->hexScrollBar->setValue(hexLocationMap[savedStringLocationMap[i]] / maxCols);
        }
    }
}

void MainWindow::removeSelected()
{
    if (fileOpened) {
        QModelIndexList selection = ui->savedStringList->selectionModel()->selectedRows();
        for (int i = 0; i < selection.count(); i++) {
            QModelIndex index = selection.at(i);
            savedStringMap[savedStringLocationMap[index.row()]] = false;
        }
        removedStrings = true;
    }
}

void MainWindow::refreshDisassembly()
{
    if (fileOpened) {

        if (!disassemblyBuilt) {

            // put opcodes in map
            QFile file("../Static-File-Analysis-Tool/OPCODES.txt");
            if (file.open(QIODevice::ReadOnly)) {
                QTextStream in(&file);
                int i = 0;
                while (!in.atEnd()) {
                    QString line = in.readLine();
                    QStringRef type(&line, 0, 1);
                    QStringRef opcode(&line, 1, line.size() - 1);
                    opTypeMap[i] = type.toInt();
                    opcodeMap[i] = opcode.toString();
                    i++;
                }
                file.close();
            }

            // find code start location (1024 is default for 32bit pe files?)
            codeStart = 1024;

            disassemblyBuilt = true;
        }

        int maxDisassemblyRows = 30;
        //int disassemblyOffset = 0; // = scrollbar value * maxDisassemblyRows, (for displaying only)
        ui->disassemblyBrowser->clear();

        int instructionSizeOffset = 0;
        QString disassemblyDisplay = "";

        // for each instruction in file
        for (int i = 0; i < maxDisassemblyRows; i++) {

            bool instructionComplete = false;
            int opcodeByte = 0, instructionStartByte = instructionSizeOffset, displacementValue = 0;
            unsigned int immediateValue = 0;

            QString instruction = "", parameters = "";
            QString line =  opcodeMap[static_cast<unsigned char>(rawData[instructionSizeOffset + codeStart])];
            int split = line.indexOf(" ");
            if (split > 0) {
                QStringRef instructionRef(&line, 0, split + 1);
                instruction = instructionRef.toString();
                QStringRef parametersRef(&line, split, line.length() - split);
                parameters = parametersRef.toString();
            }
            else {
                instruction = line;
            }

            // current byte types
            bool prefix = true, opcode = false, modByte = false, SIB = false;
            bool operandSizeModifier = false, regIsDestination = false, specialInstruction = false;
            int mod, reg, rm, scale, index, base, displacementSize = 0, immediateSize = 0, operandSize = 8, specialByte;
            QString sourceOperand = "", destinationOperand = "";

            // for each byte in instruction
            while (!instructionComplete) {

                char c = rawData[codeStart + instructionSizeOffset];
                unsigned char byte = static_cast<unsigned char>(c);

                //
                // OPTIONAL INSTRUCTION PREFIX BYTE CHECK (F0, F2, F3, 2E, 36, 3E, 26, 64, 65, 66, 67)
                //

                if (prefix) {

                    // if LOCK prefix
                    if (byte == 240) {

                    }
                    // if string manipulation prefix
                    else if (byte == 242 || byte == 243) {

                    }
                    // if segment override prefix
                    else if (byte == 46 || byte == 54 || byte == 62 || byte == 38 || byte == 100 || byte == 101) {

                    }
                    // if operand override
                    else if (byte == 102) {
                        operandSizeModifier = true;
                    }
                    // if address override
                    else if (byte == 103) {

                    }
                    else {
                        prefix = false;
                        opcode = true;
                    }
                }

                //
                // OPCODE BYTE CHECK
                //

                if (opcode && !prefix) {
                    // if extended opcode
                    if (byte == 15) {

                    }
                    else {
                        // if has mod byte
                        if (opTypeMap[byte] == 2) {
                            modByte = true;
                            // calculate if register is sender or reciever of data
                            if (byte / 10 % 2 == 1) {
                                regIsDestination = true;
                            }

                            // calculate operand size (default = 8bits)
                            if (byte % 2 == 1) {
                                if (operandSizeModifier) {
                                    operandSize = 16;
                                }
                                else {
                                    operandSize = 32;
                                }
                            }

                            // has immediate constant (defined by opcodes in Immediate Group by intel)
                            if ((byte >= 176 && byte <= 191) || (byte >= 128 && byte <= 131)) {
                                // if immediate is a one byte signed constant
                                if (byte / 10 % 2 == 1) {
                                    immediateSize = 1;
                                }
                                else {
                                    immediateSize = operandSize / 8;
                                }
                            }

                            // if instruction has multiple possible instructions
                            if ((byte >= 128 && byte <= 131) || byte == 98 || byte == 192 || byte == 193 || (byte >= 208 && byte <= 211) || byte == 216 || byte == 246 || byte == 247 || byte == 255) {
                                specialInstruction = true;
                                specialByte = byte;
                            }
                        }
                        // else if single byte instruction
                        else if (opTypeMap[byte] == 1) {
                            instructionComplete = true;
                            destinationOperand = parameters;
                        }
                        else {
                            // if has Short-Displacement jump on condition
                            if (byte >= 112 && byte <= 127) {
                                destinationOperand = "short ";
                                displacementSize = 1;
                            }
                            // if move immediate byte into byte register
                            else if (byte >= 176 && byte <= 183) {
                                immediateSize = 1;

                                // depends on opcode
                                destinationOperand = "";
                                // more needed
                            }
                            // if move immediate word/double into word/double register
                            else if (byte >= 184 && byte <= 191) {
                                int opcodeModBits;
                                opcodeModBits = (byte / static_cast<int>(pow(2, 7)) % 2) * 10;
                                opcodeModBits += (byte / static_cast<int>(pow(2, 6)) % 2);

                                if (opcodeModBits == 10) {
                                    immediateSize = 4;
                                }
                                else {
                                    // guess
                                    immediateSize = 2;
                                }

                                int opcodeRmBits;
                                opcodeRmBits = (byte / static_cast<int>(pow(2, 2)) % 2) * 100;
                                opcodeRmBits += (byte / 2 % 2) * 10;
                                opcodeRmBits += (byte % 2);
                                destinationOperand = registerName(opcodeRmBits, 32) + ", ";
                            }
                            // if single operand immediate value
                            else if (byte == 104 || byte == 232) {
                                if (operandSizeModifier) {
                                    immediateSize = 2;
                                }
                                else {
                                    immediateSize = 4;
                                }
                            }
                        }
                        opcode = false;
                        // for final display
                        opcodeByte = instructionSizeOffset;
                    }
                }

                //
                // MOD REG R/M BYTE CHECK
                //

                else if (modByte) {
                    // get addressing mode bits (first 2 bits)
                    mod = (byte / static_cast<int>(pow(2, 7)) % 2) * 10;
                    mod += (byte / static_cast<int>(pow(2, 6)) % 2);

                    // get register bits (next 3 bits)
                    reg = (byte / static_cast<int>(pow(2, 5)) % 2) * 100;
                    reg += (byte / static_cast<int>(pow(2, 4)) % 2) * 10;
                    reg += (byte / static_cast<int>(pow(2, 3)) % 2);

                    // get r/m bits (last 3 bits)
                    rm = (byte / static_cast<int>(pow(2, 2)) % 2) * 100;
                    rm += (byte / 2 % 2) * 10;
                    rm += (byte % 2);

                    if (specialInstruction) {
                        instruction = getSpecialByteInstruction(specialByte, reg);
                    }

                    // calculate addressing mode
                    if (mod == 0) {
                        if (rm == 100) {
                            // SIB no displacement
                            SIB = true;
                        }
                        else if (rm == 101) {
                            // displacement only addressing mode

                        }
                        else {
                            // register indirect addressing mode
                            if (regIsDestination) {
                                sourceOperand = "[" + registerName(rm, operandSize) + "]";
                                destinationOperand = registerName(reg, operandSize) + ", ";
                            }
                            else {
                                sourceOperand =  "[" + registerName(reg, operandSize) + "]";
                                destinationOperand = registerName(rm, operandSize) + ", ";
                            }
                            instructionComplete = true;
                        }
                    }
                    else if (mod == 1) {
                        if (rm == 100) {
                            // SIB 1 displacement byte
                            SIB = true;
                        }
                        displacementSize = 1;
                        destinationOperand = registerName(reg, operandSize) + ", ";
                        sourceOperand = "[" + registerName(rm, operandSize);
                    }
                    else if (mod == 10) {
                        if (rm == 100) {
                            // SIB 4 displacement bytes
                            SIB = true;
                        }
                        displacementSize = 4;
                        destinationOperand = registerName(reg, operandSize);
                        sourceOperand = "[" + registerName(rm, operandSize);
                    }
                    // register addressing mode
                    else if (mod == 11) {
                        // if no immediate
                        if (immediateSize == 0) {
                            if (regIsDestination) {
                                sourceOperand = registerName(rm, operandSize);
                                destinationOperand = registerName(reg, operandSize) + ", ";
                            }
                            else {
                                sourceOperand = registerName(reg, operandSize);
                                destinationOperand = registerName(rm, operandSize) + ", ";
                            }
                            instructionComplete = true;
                        }
                        else {
                            destinationOperand = registerName(rm, operandSize) + ", ";
                        }
                    }

                    modByte = false;
                }

                //
                // SIB CHECK
                //

                else if (SIB) {
                    // get scale bits (first 2 bits)
                    scale = (byte / static_cast<int>(pow(2, 7)) % 2) * 10;
                    scale += (byte / static_cast<int>(pow(2, 6)) % 2);

                    // get index bits (next 3 bits)
                    index = (byte / static_cast<int>(pow(2, 5)) % 2) * 100;
                    index += (byte / static_cast<int>(pow(2, 4)) % 2) * 10;
                    index += (byte / static_cast<int>(pow(2, 3)) % 2);

                    // get base bits (last 3 bits)
                    base = (byte / static_cast<int>(pow(2, 2)) % 2) * 100;
                    base += (byte / 2 % 2) * 10;
                    base += (byte % 2);

                    // FF only ?
                    switch (operandSize) {
                        case 16: destinationOperand = "word ptr ";
                        break;
                        case 32: destinationOperand = "dword ptr ";
                        break;
                    }

                    // get base register
                    if (mod != 101) {
                        destinationOperand += "[" + registerName(base, operandSize) + " ";
                    }
                    else if (mod == 0) {
                        // displacement only
                    }
                    else {
                         destinationOperand += "[ebp ";
                    }

                    // get index register
                    destinationOperand += "+" + registerName(index, operandSize);

                    // get index scale value
                    switch (scale) {
                        case 0: destinationOperand += "*1]";
                        break;
                        case 1: destinationOperand += "*2]";
                        break;
                        case 10: destinationOperand += "*4]";
                        break;
                        case 11: destinationOperand += "*8]";
                        break;
                    }

                    SIB = false;
                    if (displacementSize == 0) {
                        instructionComplete = true;
                    }
                }

                //
                // DISPLACEMENT BYTE CHECK
                //

                else if (displacementSize > 0) {
                    displacementValue += byte;
                    displacementSize--;
                    if (displacementSize == 0) {
                        if (destinationOperand == "short ") {
                            sourceOperand += "loc_" + QString::number(displacementValue);
                        }
                        else {
                            sourceOperand += "+" + QString::number(displacementValue) + "]";
                        }
                        instructionComplete = true;
                    }
                }

                //
                // IMMEDIATE BYTE CHECK
                //

                else if (immediateSize > 0) {
                    switch (immediateSize) {
                    case 1 : immediateValue += byte;
                    break;
                    case 2 : immediateValue += pow(16,2) * byte;
                    break;
                    case 3 : immediateValue += pow(16,4) * byte;
                    break;
                    case 4 : immediateValue += pow(16,6) * byte;
                    break;
                    }

                    immediateSize--;
                    if (immediateSize == 0) {
                        sourceOperand += QString::number(immediateValue);
                        instructionComplete = true;
                    }
                }
                else {
                    instructionComplete = true;
                }

                instructionSizeOffset++;
            }

            // tmp
            QString disassemblyLine = "";
            disassemblyLine += QString::number(instructionStartByte, 16).toUpper();
            disassemblyLine += "    ";
            disassemblyLine += instruction;
            disassemblyLine += destinationOperand;
            disassemblyLine += " ";
            disassemblyLine += sourceOperand;
            disassemblyLine += "<br>";
            disassemblyDisplay += disassemblyLine;
        }
        ui->disassemblyBrowser->setHtml(disassemblyDisplay);
    }
}

QString MainWindow::registerName(int regValue, int operandSize)
{
    QString registerName = "";
    switch (regValue) {
        case 0: switch (operandSize) {
                    case 8: registerName = "al";
                    break;
                    case 16: registerName = "ax";
                    break;
                    case 32: registerName = "eax";
                    break;
                }
        break;
        case 1: switch (operandSize) {
                    case 8: registerName = "cl";
                    break;
                    case 16: registerName = "cx";
                    break;
                    case 32: registerName = "ecx";
                    break;
                }
        break;
        case 10: switch (operandSize) {
                    case 8: registerName = "dl";
                    break;
                    case 16: registerName = "dx";
                    break;
                    case 32: registerName = "edx";
                    break;
                }
        break;
        case 11: switch (operandSize) {
                    case 8: registerName = "bl";
                    break;
                    case 16: registerName = "bx";
                    break;
                    case 32: registerName = "ebx";
                    break;
                }
        break;
        case 100: switch (operandSize) {
                    case 8: registerName = "ah";
                    break;
                    case 16: registerName = "sp";
                    break;
                    case 32: registerName = "esp";
                    break;
                }
        break;
        case 101: switch (operandSize) {
                    case 8: registerName = "ch";
                    break;
                    case 16: registerName = "bp";
                    break;
                    case 32: registerName = "ebp";
                    break;
                }
        break;
        case 110: switch (operandSize) {
                    case 8: registerName = "dh";
                    break;
                    case 16: registerName = "si";
                    break;
                    case 32: registerName = "esi";
                    break;
                }
        break;
        case 111: switch (operandSize) {
                    case 8: registerName = "bh";
                    break;
                    case 16: registerName = "di";
                    break;
                    case 32: registerName = "edi";
                    break;
                }
        break;
    }
    return registerName;
}

QString MainWindow::getSpecialByteInstruction(int specialByte, int reg)
{
    if (specialByte == 255) {
        switch (reg) {
            case 0: return "inc ";
            break;
            case 1: return "dec ";
            break;
            case 10: return "call ";
            break;
            case 11: return "callf ";
            break;
            case 100: return "jmp ";
            break;
            case 101: return "jmpf ";
            break;
            case 110: return "push ";
            break;
        }
    }
    else if (specialByte == 128 || specialByte == 129 || specialByte == 130 || specialByte == 131) {
        switch (reg) {
            case 0: return "add ";
            break;
            case 1: return "or ";
            break;
            case 10: return "adc ";
            break;
            case 11: return "sbb ";
            break;
            case 100: return "and ";
            break;
            case 101: return "sub ";
            break;
            case 110: return "xor ";
            break;
            case 111: return "cmp ";
            break;
        }
    }
    return "";
}
