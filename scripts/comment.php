<?php
$vars = $_POST;
$params=array(
    'author_name' => $vars['author_name'],
    'author_email' => $vars['author_email'],
    'author_url' => $vars['author_url'],
    'comment' => $vars['comment'],
    'done' => $vars['done'],
    'spam_detect' => getenv ( 'akismet_detect_spam' )
);
?>
<HTML>
<HEAD>
<TITLE>comment form sample</TITLE>
<META Http-Equiv="Content-Type" Content="text/html;charset=UTF-8">
</HEAD>
<BODY>
<H1 ALIGN="center">comment form</H1><P>
<FONT SIZE=5>please input comment and other information!</FONT><P>
<FORM METHOD="POST" ACTION="/comment.php">
<CENTER>
<TABLE BORDER WIDTH="90%">
    <TR>
        <TD NOWRAP>name
        </TD>
        <TD NOWRAP><INPUT TYPE="text" SIZE="40" NAME="author_name" VALUE="<?php echo $params['author_name']; ?>" >
        </TD>
    </TR>
    <TR>
        <TD NOWRAP>email
        </TD>
        <TD NOWRAP><INPUT TYPE="text" SIZE="50" NAME="author_email" VALUE="<?php echo $params['author_email']; ?>" >
        </TD>
    </TR>
    <TR>
        <TD NOWRAP>url
        </TD>
        <TD NOWRAP><INPUT TYPE="text" SIZE="40" NAME="author_url" VALUE="<?php echo $params['author_url']; ?>" >
        </TD>
    </TR>
    <TR>
        <TD VALIGN="top" NOWRAP>comment
        </TD>
        <TD NOWRAP><TEXTAREA NAME="comment" ROWS="10"COLS="35" WRAP="hard"><?php echo $params['comment']; ?></TEXTAREA>
        </TD>
    </TR>
</TABLE>
<P>
<INPUT type="submit" value="send">
<INPUT type="reset" name="clear" value="clear">
<INPUT TYPE="hidden" VALUE="1" NAME="done">


</CENTER>
</FORM>

<BR>
<PRE>
<?php
print_r($params);

if (!empty($params['done'])) {
    if ( !empty($params['spam_detect']) ) {
        echo "<p>SPAM!!!</p>";
    } else {
        echo "<p>OK!!!</p>";
    }
}
?>
</PRE>
</BODY>
</HTML>
