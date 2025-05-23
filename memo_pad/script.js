document.addEventListener('DOMContentLoaded', () => {
  const memoText = document.getElementById('memo_text');
  const saveButton = document.getElementById('save_button');
  const deleteButton = document.getElementById('delete_button');
  const memosContainer = document.getElementById('memos_container');

  // Load existing memos on page load
  loadMemos();

  saveButton.addEventListener('click', () => {
    const memo = memoText.value;
    if (memo.trim() !== '') {
      saveMemo(memo);
      memoText.value = ''; // Clear textarea
      loadMemos(); // Refresh displayed memos
    }
  });

  deleteButton.addEventListener('click', () => {
    // For now, let's assume we delete the last saved memo or a selected one.
    // This part will be more fleshed out when memo display is clearer.
    // For a simple start, let's enable deleting all memos.
    deleteAllMemos();
    loadMemos(); // Refresh displayed memos
  });

  function saveMemo(memoContent) {
    let memos = JSON.parse(localStorage.getItem('memos')) || [];
    memos.push({ id: Date.now(), text: memoContent });
    localStorage.setItem('memos', JSON.stringify(memos));
  }

  function loadMemos() {
    memosContainer.innerHTML = ''; // Clear existing memos
    let memos = JSON.parse(localStorage.getItem('memos')) || [];
    memos.forEach(memo => {
      const memoElement = document.createElement('div');
      memoElement.classList.add('memo-item'); // For styling
      memoElement.textContent = memo.text;
      // Add a delete button for each memo
      const individualDeleteButton = document.createElement('button');
      individualDeleteButton.textContent = 'Delete';
      individualDeleteButton.onclick = function() {
        deleteSingleMemo(memo.id);
      };
      memoElement.appendChild(individualDeleteButton);
      memosContainer.appendChild(memoElement);
    });
  }

  function deleteSingleMemo(memoId) {
    let memos = JSON.parse(localStorage.getItem('memos')) || [];
    memos = memos.filter(memo => memo.id !== memoId);
    localStorage.setItem('memos', JSON.stringify(memos));
    loadMemos(); // Refresh the list
  }

  function deleteAllMemos() {
    localStorage.removeItem('memos');
  }
});
