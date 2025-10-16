function sortBooks(books, byTitle) {

    if (byTitle) {
        return books.sort((a, b) => a.title.localeCompare(b.title));
    }
    else {
        return books.sort((a, b) => a.author.localeCompare(b.author));
    }

}
