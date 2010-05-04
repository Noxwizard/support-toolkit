<?php
/**
*
* @package Support Toolkit - Database Cleaner
* @version $Id$
* @copyright (c) 2009 phpBB Group
* @license http://opensource.org/licenses/gpl-license.php GNU Public License
*
*/

/**
 * @ignore
 */
if (!defined('IN_PHPBB'))
{
	exit;
}

/**
* phpBB 3.0.2 data file
*/
class datafile_3_0_2
{
	/**
	* @var Array The bots
	*/
	var $bots = array(
		// No bot changes 3.0.1 -> 3.0.2
	);

	/**
	* @var Array 3.0.2 config data
	*/
	var $config_data = array(
		'referer_validation'		=> array('config_value' => '1', 'is_dynamic' => '0'),
		'check_attachment_content'	=> array('config_value' => '1', 'is_dynamic' => '0'),
		'mime_triggers'				=> array('config_value' => 'body|head|html|img|plaintext|a href|pre|script|table|title', 'is_dynamic' => '0'),
	);

	/**
	* @var Array All default permission settings
	*/
	var $permissions = array(
		// No permission changes 3.0.1 -> 3.0.2
	);

	/**
	* @var Array All default Modules (formatted to work with UMIL Auto Module inserter, it shouldn't be too long)
	*/
	var $modules = array(
		// No Module changes 3.0.1 -> 3.0.2
	);

	/**
	* @var Arra All default groups
	*/
	var $groups = array(
		// No Group changes 3.0.1 -> 3.0.2
	);

	/**
	* Define the basic structure
	* The format:
	*		array('{TABLE_NAME}' => {TABLE_DATA})
	*		{TABLE_DATA}:
	*			COLUMNS = array({column_name} = array({column_type}, {default}, {auto_increment}))
	*			PRIMARY_KEY = {column_name(s)}
	*			KEYS = array({key_name} = array({key_type}, {column_name(s)})),
	*
	*	Column Types:
	*	INT:x		=> SIGNED int(x)
	*	BINT		=> BIGINT
	*	UINT		=> mediumint(8) UNSIGNED
	*	UINT:x		=> int(x) UNSIGNED
	*	TINT:x		=> tinyint(x)
	*	USINT		=> smallint(4) UNSIGNED (for _order columns)
	*	BOOL		=> tinyint(1) UNSIGNED
	*	VCHAR		=> varchar(255)
	*	CHAR:x		=> char(x)
	*	XSTEXT_UNI	=> text for storing 100 characters (topic_title for example)
	*	STEXT_UNI	=> text for storing 255 characters (normal input field with a max of 255 single-byte chars) - same as VCHAR_UNI
	*	TEXT_UNI	=> text for storing 3000 characters (short text, descriptions, comments, etc.)
	*	MTEXT_UNI	=> mediumtext (post text, large text)
	*	VCHAR:x		=> varchar(x)
	*	TIMESTAMP	=> int(11) UNSIGNED
	*	DECIMAL		=> decimal number (5,2)
	*	DECIMAL:	=> decimal number (x,2)
	*	PDECIMAL	=> precision decimal number (6,3)
	*	PDECIMAL:	=> precision decimal number (x,3)
	*	VCHAR_UNI	=> varchar(255) BINARY
	*	VCHAR_CI	=> varchar_ci for postgresql, others VCHAR
	*/
	function get_schema_struct(&$schema_data)
	{
		// Column change
		$schema_data['phpbb_drafts']['COLUMNS']['draft_subject']			= array('STEXT_UNI', '');
		$schema_data['phpbb_forums']['COLUMNS']['forum_last_post_subject']	= array('STEXT_UNI', '');
		$schema_data['phpbb_posts']['COLUMNS']['post_subject']				= array('STEXT_UNI', '');
		$schema_data['phpbb_privmsgs']['COLUMNS']['message_subject']		= array('STEXT_UNI', '');
		$schema_data['phpbb_topics']['COLUMNS']['topic_title']				= array('STEXT_UNI', '');
		$schema_data['phpbb_topics']['COLUMNS']['topic_last_post_subject']	= array('STEXT_UNI', '');

		// Key change
		unset($schema_data['phpbb_sessions']['KEYS']['session_forum_id']);
		$schema_data['phpbb_sessions']['KEYS']['session_fid']				= array('INDEX', 'session_forum_id');
	}
}