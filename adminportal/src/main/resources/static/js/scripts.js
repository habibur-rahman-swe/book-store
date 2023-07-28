$(document).ready(function() {
  $('.delete-book').on('click', function() {
    var path = 'remove';
    var id = $(this).attr('id');
    bootbox.confirm({
      message: "Are you sure to remove this book? It can't be undone.",
      buttons: {
        cancel: {
          label: '<i class="fa fa-times"></i> Cancel'
        },
        confirm: {
          label: '<i class="fa fa-check"></i> Confirm'
        }
      },
      callback: function(confirmed) {
        if (confirmed) {
          $.post(path, {'id': id}, function(res) {
            location.reload();
          });
        }
      }
    });
  });

  $('#deleteSelected').click(function() {
    var idList = $('.checkboxBook');
    var bookIdList = [];
    for (var i = 0; i < idList.length; i++) {
      if (idList[i].checked) {
        bookIdList.push(idList[i]['id']);
      }
    }

    console.log(bookIdList);

    var path = 'removeList';
    $.ajax({
      type: 'POST',
      url: path,
      data: bookIdList,
      contentType: 'application/json',
      success: function(res) {
        console.log(res);
        location.reload();
      },
      error: function(res) {
        console.log(res);
        location.reload();
      }
    });
  });

  $("#selectAllBooks").click(function() {
    if ($(this).prop('checked') === true) {
      $(".checkboxBook").prop('checked', true);
    } else if ($(this).prop('checked') === false) {
      $(".checkboxBook").prop('checked', false);
    }
  });
});
