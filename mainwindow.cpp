#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "dialogbox.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->stackedWidget->setCurrentIndex(0);

    basicWindowName = "Static File Analysis Tool";

    backupBuilt = false;
    hashBuilt = false;
    packChecked = false;
    packPacked = false;
    packUnpacked = false;

    fileOpened = false;
    stringsBuilt = false;
    stringsDisplayed = false;
    stringsSaved = false;
    dllsBuilt = false;
    hexBuilt = false;
    checklistBuilt = false;

    fileHash = "";
    backupLoc = "";

    refreshWindow();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionGenerate_Hash_triggered()
{
    DialogBox dialogBox;
    dialogBox.setWindowTitle("Hash");
    QLabel *label = new QLabel(&dialogBox);

    if (fileOpened) {
        if (!hashBuilt) {
            fileHash = generateHash(rawData, fileSize);
            label->setText("The SHA-1 hash of the current file is:\n" + fileHash);
        }
    }
    else {
        label->setText("No file is selected.");
    }

    dialogBox.exec();

    hashBuilt = true;
    refreshWindow();
}

QString MainWindow::generateHash(char *data , int size)
{
    QCryptographicHash hash(QCryptographicHash::Sha1);
    hash.addData(data, size);
    QByteArray hashArray = hash.result();
    QString hashString = hashArray.toHex();
    hashString = hashString.toUpper();
    return hashString;
}

void MainWindow::on_actionCreate_Backup_triggered()
{
    DialogBox dialogBox;
    dialogBox.setWindowTitle("Backup");
    QLabel *label = new QLabel(&dialogBox);

    if (fileOpened) {
        QDir dir;

        if (backupLoc == "") {
            label->setText("Please select a location to store backups.");
            dialogBox.exec();
            QFile file(QFileDialog::getExistingDirectory(this, "Select a location to store backups."));
            backupLoc = file.fileName();
            dir.setPath(backupLoc);
        }

        if (backupLoc != "") {
            if (!hashBuilt) {
                fileHash = generateHash(rawData, fileSize);
            }

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
                label->setText("A backup of this file already exists.");
            }
            else {
                // create backup
                QString fullName = backupLoc + 92 + backupName;
                QFile file(fullName);
                QString verificationHash;

                if (file.open(QIODevice::ReadWrite))
                {
                    QDataStream ds(&file);
                    ds.writeRawData(rawData, fileSize);


                    // temp
                    verificationHash = fileHash;
                    /*
                    // verify data
                    int size = file.size();
                    data = new char[size];

                    QDataStream rs(&file);
                    rs.readRawData(data, size);

                    verificationHash = generateHash(data, size);
                    */
                    file.close();
                }

                if (verificationHash == fileHash) {
                    label->setText("Backup Succesful.\n" + fileName + "\nhas been saved as\n" + fileHash + ".bak");
                }
                else {
                    label->setText("Backup Failed Succesfully.\n" + fileName + "\nhas been saved as\n" + fileHash + ".bak\nhowever the backup is does not match the original file.");
                }
            }
            backupBuilt = true;
        }
        else {
            label->setText("No location selected.");
        }
        dialogBox.exec();
    }
    else {
        label->setText("You must first select a file to analyse before anything can be backed up.");
        dialogBox.exec();
    }

    refreshWindow();
}

void MainWindow::on_actionCheck_if_Packed_triggered()
{
    DialogBox dialogBox;
    dialogBox.setWindowTitle("Check if File is Packed");
    QLabel *label = new QLabel(&dialogBox);

    if (fileOpened) {

        if (!packChecked) {

            if (isPacked()) {
                label->setText("The current file IS packed using UPX.");
            }

        }
        else {
            label->setText("The current file is NOT packed using UPX.");
        }
    }
    else {
        label->setText("No file is selected.");
    }


    dialogBox.exec();

    packChecked = true;
    refreshWindow();
}

bool MainWindow::isPacked()
{





    return true;
}

void MainWindow::on_actionPack_triggered()
{
    DialogBox dialogBox;
    dialogBox.setWindowTitle("Pack");
    dialogBox.exec();

    packPacked = true;
    refreshWindow();
}

void MainWindow::on_actionUnpack_triggered()
{
    DialogBox dialogBox;
    dialogBox.setWindowTitle("Unpack");
    dialogBox.exec();

    packUnpacked = true;
    refreshWindow();
}

void MainWindow::on_actionChecklistMain_triggered()
{
    ui->stackedWidget->setCurrentIndex(6);
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

void MainWindow::on_actionHex_triggered()
{
    // CAN FIT MAX 4GB FILE (row name combinations)
    ui->stackedWidget->setCurrentIndex(4);
    ui->hexTable->horizontalHeader()->resizeSection(17, 150);
    refreshWindow();

}

void MainWindow::on_actionOpen_triggered()
{
    // cancelling this throws exception
    QFile file(QFileDialog::getOpenFileName(this, "Select a file to analyse", "D:/Downloads"));

    if (file.open(QIODevice::ReadOnly)) {

        QDataStream ds(&file);

        // if file too big eg. over 4GB, kill here, display too big
        fileSize = file.size();
        rawData = new char[fileSize];
        ds.readRawData(rawData, fileSize);
        file.close();

        // MAKE OWN FUNCTION
        // reset checks
        backupBuilt = false;
        hashBuilt = false;
        packChecked = false;
        packPacked = false;
        packUnpacked = false;
        fileOpened = true;
        stringsBuilt = false;
        stringsSaved = false;
        dllsBuilt = false;
        hexBuilt = false;
        checklistBuilt = false;
        ui->hexScrollBar->setValue(0);
        strings.clear();

        // get file name
        QString fullFileName = file.fileName();
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
        }

        basicWindowName = "Static File Analysis Tool - " + fileName;
        refreshWindow();
    }
}

void MainWindow::on_actionDisassembly_triggered()
{
    ui->stackedWidget->setCurrentIndex(5);
    refreshWindow();
}

void MainWindow::refreshHex()
{
    if (fileOpened) {

        ui->hexTable->clearContents();

        int rowNameLength = 8;
        int displayCols = 16;
        int displayRows = 16;
        int maxCols = 16;
        int dataStartPoint = ui->hexScrollBar->value();

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
                displayRows = fileSize / displayRows + 1;
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
        hexBuilt = true;
    }
}

void MainWindow::findStrings()
{
    if (!stringsBuilt && fileOpened) {

        QString item;
        stringCount = 0;
        bool nullSpaced = false;
        int stringLength = 3;

        // for each char in file
        for (int i = 0; i < fileSize; i++) {

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
                    if (item.size() == 1 && i + 1 < fileSize) {
                        char tmpc = rawData[i + 1];
                        unsigned char tmpuc = static_cast<unsigned char>(tmpc);
                        if (tmpuc >= 32 && tmpuc <= 126) {
                            nullSpaced = true;
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
                                    strings.insert(stringCount,item);
                                    stringCount++;
                                    item = "";
                                }
                            }
                        }
                    }
                    else if (item.size() >= stringLength) {
                        strings.insert(stringCount,item);
                        stringCount++;
                        item = "";
                    }
                    else {
                        item = "";
                    }
                }
                else if (item.size() >= stringLength) {
                    strings.insert(stringCount,item);
                    stringCount++;
                    item = "";
                }
                else {
                    item = "";
                }
            }
        }

        // display things
        QString count = QString::number(stringCount);
        ui->stringCountValue->setText(count);

        stringsBuilt = true;
    }
}

void MainWindow::refreshStrings()
{
    if (fileOpened) {

        saveDisplayedStrings();

        maxDisplayStrings = 24;
        int displayStringCount = maxDisplayStrings;
        stringOffset = ui->stringsScrollBar->value() * maxDisplayStrings;

        ui->stringsScrollBar->setMaximum(stringCount / maxDisplayStrings);
        ui->stringList->clear();

        if (ui->stringsScrollBar->value() == ui->stringsScrollBar->maximum()) {
            if (stringCount % maxDisplayStrings > 0) {
                displayStringCount = stringCount % maxDisplayStrings;
            }
        }

        //build checkboxlist
        QStringList displayStrings;
        for (int i = 0; i < displayStringCount; i++) {
            displayStrings.insert(i, strings[stringOffset + i]);
        }

        ui->stringList->addItems(displayStrings);

        for(int i = 0; i < displayStringCount; i++) {
            ui->stringList->item(i)->setCheckState(Qt::Unchecked);
        }

        // recheck saved strings
        for(int i = 0; i < displayStringCount; i++) {
            if (savedStringMap[i + stringOffset]) {
                ui->stringList->item(i)->setCheckState(Qt::Checked);
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
    }
}

void MainWindow::saveDisplayedStrings()
{
    if (ui->stringList->count() > 0) {
        for (int i =0; i < ui->stringList->count(); i++) {
            if (ui->stringList->item(i)->checkState()) {
                savedStringMap[i + stringOffset] = true;
            }
            else {
                savedStringMap[i + stringOffset] = false;
            }
        }
    }
}

void MainWindow::refreshSavedStrings()
{
    if (stringsBuilt) {
        QStringList savedStrings;
        for (int i = 0; i < stringCount; i++) {
            if (savedStringMap[i]) {
               savedStrings.insert(savedStrings.count(), strings[i]);
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

void MainWindow::on_stringsScrollBar_valueChanged()
{
    refreshStrings();
}

void MainWindow::on_hexScrollBar_valueChanged()
{
    refreshHex();
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

void MainWindow::on_actionDLL_s_triggered()
{
    ui->stackedWidget->setCurrentIndex(3);
    refreshWindow();
}

void MainWindow::findDLLs()
{

    if (!stringsBuilt) {
        findStrings();
    }

    if (!dllsBuilt) {
        ui->DLL_List->clear();
        QStringList dlls;

        // for each string found
        for (int i = 0; i < stringCount; i++) {

            QString string = strings[i];
            QStringRef subString(&string, string.length() - 4, 4);

            if (subString == ".dll" || subString == ".DLL") {
                dlls += string;
            }
        }

        dlls.removeDuplicates();
        ui->DLL_List->addItems(dlls);
        dllsBuilt = true;
    }
}

void MainWindow::refreshChecklist()
{
    if (fileOpened) {

        if (!checklistBuilt) {
            ui->checklistFileNameValue->setText(fileName);
            ui->checklistFileHashValue->setText(fileHash);

            // uncheck all steps
            for (int i = 0; i < ui->checklistMainStepsList->count(); i++) {
                ui->checklistMainStepsList->item(i)->setCheckState(Qt::Unchecked);
            }

            ui->checklistMainStepsList->item(0)->setCheckState(Qt::Checked);
            checklistBuilt = true;
        }

        // progress bar stuff
        int progress = 1;

        if (hashBuilt) {
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

        // update progress bar
        int steps = 9;
        int percent = progress * 100 / steps;
        ui->checklistProgressBar->setValue(percent);
    }
}

void MainWindow::refreshWindow()
{
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

        case 5: extendedWindowName = " - Disassembly";
        break;

        case 6: extendedWindowName = " - Checklist";
        refreshChecklist();
        break;
    }

    // window name
    this->setWindowTitle(basicWindowName + extendedWindowName);
}

void MainWindow::on_actionSeperate_Window_triggered()
{
    ui->stackedWidget->setCurrentIndex(7);
}

void MainWindow::on_stringSearchButton_clicked()
{
    if (stringsBuilt) {

        QString search = ui->searchString->text();
        if (stringsAdvancedSearchString != search) {
            stringsAdvancedSearchIterator = 0;
        }
        stringsAdvancedSearchString = search;

        bool found = false;
        while (!found && stringsAdvancedSearchIterator < stringCount) {

            //
            // starting search icon






            //

            QString searching = strings[stringsAdvancedSearchIterator];
            int searchLength = search.length();
            int searchedLength = strings[stringsAdvancedSearchIterator].length();

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
            stringsAdvancedSearchIterator++;
        }

        //
        // finished search icon





        //

        if (found) {
            if (stringsAdvancedSearchIterator % maxDisplayStrings == 0) {
                ui->stringsScrollBar->setValue((stringsAdvancedSearchIterator / maxDisplayStrings) - 1);
            }
            else {
                ui->stringsScrollBar->setValue(stringsAdvancedSearchIterator / maxDisplayStrings);
            }
            // highlight string
            //qDebug() << "search string: " << stringsAdvancedSearchIterator;
            //qDebug() << "search string: " << strings[stringsAdvancedSearchIterator - 1];
            //ui->stringList->item((stringsAdvancedSearchIterator % maxDisplayStrings - 1 + maxDisplayStrings) % maxDisplayStrings)->setSelected(true);
            ui->stringList->item((stringsAdvancedSearchIterator % maxDisplayStrings - 1 + maxDisplayStrings) % maxDisplayStrings)->setCheckState(Qt::Checked);
            //ui->stringList->setFocus();
            refreshStrings();
        }
        else if (stringsAdvancedSearchIterator == stringCount) {
            stringsAdvancedSearchIterator = 0;
        }
    }
}
