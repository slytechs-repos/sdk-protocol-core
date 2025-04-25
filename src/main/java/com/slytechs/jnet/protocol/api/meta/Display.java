/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.protocol.api.meta;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;

import java.lang.annotation.Repeatable;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import com.slytechs.jnet.platform.api.util.format.Detail;

/**
 * The Interface Display.
 *
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 */
@Repeatable(Displays.class)
@Retention(RUNTIME)
@Target({ METHOD,
		FIELD,
		TYPE })
public @interface Display {

	/**
	 * Format string where arguments passed to this format string are as follows:
	 * 
	 * <dl>
	 * <dt>1st arg of type <code>Object</code>: 1$ ie. "%1$X"</dt>
	 * <dd>native field value object</dd>
	 * <dt>2nd arg of type <code>String></code>: 2$ ie "%2$s"</dt>
	 * <dd>formatted field value</dd>
	 * <dt>3rd arg of type <code>String</code>: 3$ ie "%3$s"</dt>
	 * <dd>mapped/resolved/looked up value, such as DNS resolution, etc...</dd>
	 * </dl>
	 * 
	 * <p>
	 * For example: <code>"0x%1$04X (formatted=%2$s, resolved=%3$s)"</code> or
	 * arguments can be accessed without absolute indexes since they are accessed in
	 * order<code>"0x04X (formatted=%s, resolved=%s)</code>
	 * </p>
	 * 
	 *
	 * @return the string
	 */
	String value() default "";

	/**
	 * Label.
	 *
	 * @return the string
	 */
	String label() default "";

	/**
	 * Detail.
	 *
	 * @return the detail
	 */
	Detail detail() default Detail.HIGH;

	/**
	 * Flag which indicates if this element should display inherited fields from
	 * super class.
	 *
	 * @return true, if it should display, otherwise false
	 */
	String[] hide() default {};

	/**
	 * Multiline display. Each line is formatted and displayed below the main
	 * display. Typically used for displaying bitmaps and bit-fields. such as
	 * 
	 * <pre>
	 * Flags: 0xc0000000, Router, Solicited
	 *    1... .... .... .... .... .... .... .... = Router: Set
	 *    .1.. .... .... .... .... .... .... .... = Solicited: Set
	 *    ..0. .... .... .... .... .... .... .... = Override: Not set
	 *    ...0 0000 0000 0000 0000 0000 0000 0000 = Reserved: 0
	 * </pre>
	 *
	 * @return the string[]
	 */
	String[] multiline() default {};
}
